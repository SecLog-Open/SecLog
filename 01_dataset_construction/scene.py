import subprocess
import sys
import tempfile
import time
from typing import Any

import yaml
from rich import print

from logs import assert_logging_healthy, start_logging
from modify import do_modify_after, do_modify_pre
from schema import Operation, Scene
from utils import client, exec_command, get_current_time

project: str | None = None


def modify_compose(scene: Scene) -> dict[str, Any]:
    compose = scene.model_dump(by_alias=True)

    compose["version"] = "3.9"

    return compose


def stop_scene():
    global project
    if project is not None:
        exec_command(["docker", "compose", "--file", project, "kill"])
        exec_command(["docker", "compose", "--file", project, "down", "-v"])
        project = None


def get_service_to_container_id_mapping(services: list[str], container_ids: list[str]):
    service_to_container_id: dict[str, str] = {}
    for container_id in container_ids:
        container_info = client.containers.get(container_id).attrs
        service_name = container_info["Config"]["Labels"].get(
            "com.docker.compose.service"
        )
        if service_name in services:
            service_to_container_id[service_name] = container_id[:12]
    return service_to_container_id


def run_base_scene(scene: Scene):
    global project

    print("[Running Base Scene]")
    compose = modify_compose(scene)
    print(compose)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", prefix=f"scene_{get_current_time()}_", delete=False
    ) as f:
        yaml.dump(compose, f)
        project = f.name
        print(project)

    exec_command(["docker", "compose", "--file", project, "up", "--build", "-d"])

    output = subprocess.check_output(
        ["docker", "compose", "--file", project, "ps", "-q"]
    )
    container_ids = output.decode().strip().split("\n")

    print("Services started, waiting for them to become healthy...")

    # Wait until all containers are healthy or running without a health check.
    all_healthy = False
    max_wait_time = 600  # Allow up to ten minutes for startup.
    start_time = time.time()
    check_count = 0
    
    while not all_healthy:
        check_count += 1
        all_healthy = True
        unhealthy_containers = []
        
        for container_id in container_ids:
            container = client.containers.get(container_id)
            container.reload()
            container_name = container.name
            health_status = container.attrs["State"].get("Health", {}).get("Status")
            container_status = container.status
            
            if health_status:
                # Inspect the configured container health check.
                if health_status != "healthy":
                    all_healthy = False
                    health_log = container.attrs["State"].get("Health", {}).get("Log", [])
                    last_log = health_log[-1] if health_log else {}
                    unhealthy_containers.append(
                        f"{container_name}: {health_status} (last check: {last_log.get('Output', 'N/A')[:100]})"
                    )
            else:
                # Without a health check, require only a running container.
                if container_status != "running":
                    all_healthy = False
                    unhealthy_containers.append(f"{container_name}: {container_status}")

        if not all_healthy:
            elapsed_time = time.time() - start_time
            if elapsed_time > max_wait_time:
                print(f"\n⚠️  Timeout after {max_wait_time}s. Unhealthy containers:")
                for info in unhealthy_containers:
                    print(f"  - {info}")
                raise RuntimeError(f"Some containers failed to become healthy within {max_wait_time} seconds")
            
            if check_count % 6 == 0:  # Log detailed status every thirty seconds.
                print(f"\n⏳ Still waiting... ({int(elapsed_time)}s elapsed). Unhealthy containers:")
                for info in unhealthy_containers:
                    print(f"  - {info}")
            else:
                print("Not all services are healthy yet, waiting...")
            time.sleep(5)  # Poll every five seconds.

    print("All services are healthy!")
    return get_service_to_container_id_mapping(
        list(scene.services.keys()), container_ids
    )


def execute_steps(service_to_container_id: dict[str, str], steps: list[Operation]):

    def execute_attack_step(container_id: str, step: Operation, env: dict[str, str]):
        container = client.containers.get(container_id)
        step_command = " ".join(step.command)
        print(
            f"[Attack Step] scheduled name={step.name} container={container_id} command={step_command}"
        )

        if step.blocking:
            res = container.exec_run(step.command, environment=env)
            output = res.output.decode(errors="replace") if isinstance(res.output, bytes) else str(res.output)
            if output:
                print(output, end="")
            if res.exit_code != 0:
                raise RuntimeError(
                    f"[Attack Step] exited non-zero in blocking mode: "
                    f"name={step.name} exit_code={res.exit_code} command={step_command}"
                )
            print(
                f"[Attack Step] completed successfully (blocking) "
                f"name={step.name} exit_code=0"
            )
            return

        try:
            exec_info = client.api.exec_create(
                container=container.id,
                cmd=step.command,
                environment=env,
            )
            exec_id = exec_info.get("Id")
            if not exec_id:
                raise RuntimeError("missing exec id from docker exec_create")

            print(
                f"[Attack Step] exec created name={step.name} exec_id={exec_id}"
            )
            client.api.exec_start(exec_id, detach=True, stream=False)
            print(
                f"[Attack Step] startup requested (detached) name={step.name} exec_id={exec_id}"
            )

            time.sleep(1.0)
            inspect = client.api.exec_inspect(exec_id)
            running = bool(inspect.get("Running", False))
            exit_code = inspect.get("ExitCode")

            if running:
                print(
                    f"[Attack Step] startup success name={step.name} exec_id={exec_id} running=true"
                )
                return

            if exit_code is None:
                raise RuntimeError(
                    f"[Attack Step] startup status unknown: "
                    f"name={step.name} exec_id={exec_id} inspect={inspect}"
                )

            if exit_code != 0:
                raise RuntimeError(
                    f"[Attack Step] exited non-zero shortly after startup: "
                    f"name={step.name} exec_id={exec_id} exit_code={exit_code}"
                )

            print(
                f"[Attack Step] finished quickly with exit_code=0 "
                f"name={step.name} exec_id={exec_id}"
            )
        except Exception as exc:
            print(f"[Attack Step] startup failure name={step.name} error={exc}")
            raise

    for step in steps:
        assert_logging_healthy()
        print(f"[Executing Step] {step.name}")
        print(step.model_dump(by_alias=True))
        container_id = service_to_container_id[step.service]
        env = {"LD_PRELOAD": "/hook_glibc_applog.so"}
        if step.is_attack:
            env["LD_PRELOAD"] += " /hook_glibc_attacker.so"
            execute_attack_step(container_id, step, env)
            assert_logging_healthy()
            continue

        container = client.containers.get(container_id)
        if step.blocking:
            res = container.exec_run(step.command, environment=env, stream=True)
            for output in res.output:
                print(output.decode(), end="")
                sys.stdout.flush()
                assert_logging_healthy()
        else:
            container.exec_run(step.command, detach=True, environment=env)
        assert_logging_healthy()


def start_scene(scene: Scene) -> tuple[dict[str, str], dict[str, str]]:
    service_to_container_id = {}  # Keep cleanup safe if startup fails.
    inv_dict = {}  # Keep cleanup safe before the reverse map is populated.
    
    try:
        with do_modify_pre(scene) as pre_ret:
            scene, inv_dict, cur_path = pre_ret
            service_to_container_id = run_base_scene(scene)  # Start the base scene.
            with do_modify_after(
                scene, service_to_container_id, inv_dict, cur_path
            ):  # Apply post-start configuration.
                start_logging(service_to_container_id)  # Start log capture.
                execute_steps(service_to_container_id, scene.steps)
                assert_logging_healthy()
                print("All steps executed, waiting for logs to be recorded...")
                time.sleep(5)  # Allow log capture to finish flushing.
                assert_logging_healthy()
    except Exception as e:
        # Release scene resources even if execution raises an exception.
        print(f"Error in start_scene: {e}")
        raise

    return service_to_container_id, inv_dict
