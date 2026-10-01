import os
import tempfile
from contextlib import contextmanager
from typing import Any, Generator

from logs import add_app_log
from loguru import logger
from rich import print
from schema import Scene
from utils import exec_command, invert_ip


def _inject_php_hook(service: dict, hook_host_path: str, php_ini_host_path: str) -> None:
    """Helper: inject PHP hook into a service."""
    service.setdefault("volumes", []).append(
        f"{hook_host_path}:/usr/local/etc/php/furina_hook.php:ro"
    )
    service.setdefault("volumes", []).append(
        f"{php_ini_host_path}:/usr/local/etc/php/conf.d/zz-furina-auto-prepend.ini:ro"
    )


def _service_fingerprint(service_name: str, service: dict) -> str:
    """Build a stable fingerprint from service metadata for matching."""
    parts: list[str] = [str(service_name)]

    container_name = service.get("container_name")
    if container_name:
        parts.append(str(container_name))

    image = service.get("image")
    if image:
        parts.append(str(image))

    build = service.get("build")
    if isinstance(build, dict):
        context = build.get("context")
        dockerfile = build.get("dockerfile")
        if context:
            parts.append(str(context))
        if dockerfile:
            parts.append(str(dockerfile))
    elif isinstance(build, str):
        parts.append(build)

    return " ".join(parts).lower()


def _is_web_service(service_name: str, service: dict) -> bool:
    service_name_lower = service_name.lower()
    container_name = str(service.get("container_name", "")).lower()
    return (
        service_name_lower.endswith("-web")
        or "-web-" in service_name_lower
        or container_name.endswith("-web")
        or "-web-" in container_name
    )


def _service_matches_scene_tags(service_name: str, service: dict, tags: set[str]) -> bool:
    fp = _service_fingerprint(service_name, service)
    return any(tag in fp for tag in tags)


def _normalize_environment_to_dict(environment: Any) -> dict[str, str]:
    """Normalize docker-compose environment to dict, preserving known entries."""
    if isinstance(environment, dict):
        return {str(k): str(v) for k, v in environment.items()}

    if isinstance(environment, list):
        env_dict: dict[str, str] = {}
        for item in environment:
            if isinstance(item, dict):
                for k, v in item.items():
                    env_dict[str(k)] = str(v)
                continue

            if isinstance(item, str):
                if "=" in item:
                    key, value = item.split("=", 1)
                    key = key.strip()
                    if key:
                        env_dict[key] = value
                else:
                    key = item.strip()
                    if key and key not in env_dict:
                        env_dict[key] = ""
        return env_dict

    return {}


def _append_java_tool_options(existing: str, required_opt: str) -> str:
    existing = existing.strip()
    if not existing:
        return required_opt
    if required_opt in existing.split():
        return existing
    return f"{existing} {required_opt}"


def _append_ld_library_path(existing: str, required_path: str) -> str:
    existing = existing.strip()
    if not existing:
        return required_path

    paths = [p for p in existing.split(":") if p]
    if required_path in paths:
        return existing
    return f"{existing}:{required_path}"


def hook_php_gitlist(scene: Scene, cur_path: str) -> Scene:
    context_path = os.environ.get("CONTEXT_PATH", "")
    normalized_context_path = os.path.normpath(os.path.abspath(context_path))
    
    # Single-scene target paths
    target_scene_paths = {
        # gitlist
        os.path.normpath(
            os.path.abspath("./example/vulhub/gitlist/CVE-2018-1000533")
        ),
        # joomla
        os.path.normpath(
            os.path.abspath("./example/vulhub/joomla/CVE-2015-8562")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/joomla/CVE-2017-8917")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/joomla/CVE-2023-23752")
        ),
        # cmsms
        os.path.normpath(
            os.path.abspath("./example/vulhub/cmsms/CVE-2019-9053")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/cmsms/CVE-2021-26120-lab")
        ),
        # adminer
        os.path.normpath(
            os.path.abspath("./example/vulhub/adminer/CVE-2021-43008")
        ),
    }

    multi_jump_path = os.path.normpath(
        os.path.abspath("./example/multi-jump")
    )
    is_multi_jump = normalized_context_path == multi_jump_path
    is_single_scene = normalized_context_path in target_scene_paths

    if not (is_single_scene or is_multi_jump):
        return scene

    print("[Hook PHP Gitlist]")

    hook_host_path = f"{cur_path}/furina_hook.php"
    php_ini_host_path = f"{cur_path}/zz-furina-auto-prepend.ini"

    hook_content = """<?php
if (!defined('FURINA_PHP_HOOK_LOADED')) {
    define('FURINA_PHP_HOOK_LOADED', true);

    function furina_php_new_request_id() {
        static $counter = 0;
        $counter++;
        return sprintf(
            '%s-%d-%d',
            (string) getmypid(),
            $counter,
            (int) floor(microtime(true) * 1000000)
        );
    }

    function furina_php_open_marker_stream() {
        static $markerStream = null;

        if ($markerStream === null) {
            $markerStream = @fopen('/dev/null', 'wb');
        }

        return $markerStream;
    }

    function furina_php_detect_handler_key() {
        $script = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '';
        $method = isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : '';
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';

        $uriPath = parse_url($uri, PHP_URL_PATH);
        if (!is_string($uriPath)) {
            $uriPath = '';
        }

        $parts = array();
        foreach (array($script, $method, $uriPath) as $item) {
            if ($item !== '') {
                $parts[] = $item;
            }
        }

        return implode('|', $parts);
    }

    function furina_php_emit_marker($action, $requestId, $handlerKey) {
        $stream = furina_php_open_marker_stream();
        if ($stream === false || $stream === null) {
            return;
        }

        $payload = sprintf('furina-php-ins %s %s', $action, $requestId);
        if ($handlerKey !== '') {
            $payload .= ' ' . $handlerKey;
        }

        @fwrite($stream, $payload);
        @fflush($stream);
    }

    function furina_php_shutdown_marker($requestId, $handlerKey) {
        furina_php_emit_marker('request_end', $requestId, $handlerKey);
    }

    $furinaPhpRequestId = furina_php_new_request_id();
    $furinaPhpHandlerKey = furina_php_detect_handler_key();

    furina_php_emit_marker('hook_loaded', $furinaPhpRequestId, $furinaPhpHandlerKey);
    furina_php_emit_marker('request_begin', $furinaPhpRequestId, $furinaPhpHandlerKey);
    register_shutdown_function('furina_php_shutdown_marker', $furinaPhpRequestId, $furinaPhpHandlerKey);
}
"""

    with open(hook_host_path, "w", encoding="utf-8") as file:
        file.write(hook_content)

    with open(php_ini_host_path, "w", encoding="utf-8") as file:
        file.write("auto_prepend_file=/usr/local/etc/php/furina_hook.php\n")

    if is_single_scene:
        # Single-scene mode: inject into service named "web"
        web_service = scene.services.get("web")
        if not web_service:
            return scene
        _inject_php_hook(web_service, hook_host_path, php_ini_host_path)
    
    elif is_multi_jump:
        # Multi-jump mode: only include services enabled in root multi-jump scene
        php_scene_tags = {
            "gitlist-2018-1000533",
            "gitlist/cve-2018-1000533",
            "joomla-cve-2015-8562",
            "joomla/cve-2015-8562",
        }
        for service_name, service in scene.services.items():
            if not _is_web_service(service_name, service):
                continue
            if not _service_matches_scene_tags(service_name, service, php_scene_tags):
                continue
            print(f"  Injecting PHP hook into service: {service_name}")
            _inject_php_hook(service, hook_host_path, php_ini_host_path)

    return scene


def _inject_java_hook(service: dict) -> None:
    """Helper: inject Java agent environment variables into a service."""
    envs = _normalize_environment_to_dict(service.get("environment", {}))

    envs["JAVA_TOOL_OPTIONS"] = _append_java_tool_options(
        str(envs.get("JAVA_TOOL_OPTIONS", "")),
        "-javaagent:/java-agent.jar",
    )
    envs["LD_LIBRARY_PATH"] = _append_ld_library_path(
        str(envs.get("LD_LIBRARY_PATH", "")),
        "/quicklog",
    )

    service["environment"] = envs


def hook_java_apps(scene: Scene, cur_path: str) -> Scene:
    context_path = os.environ.get("CONTEXT_PATH", "")
    normalized_context_path = os.path.normpath(os.path.abspath(context_path))
    
    # Single-scene target paths
    target_scene_paths = {
        # geoserver
        os.path.normpath(
            os.path.abspath("./example/vulhub/geoserver/CVE-2023-25157")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/geoserver/CVE-2024-36401")
        ),
        # metabase
        os.path.normpath(
            os.path.abspath("./example/vulhub/metabase/CVE-2021-41277")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/metabase/CVE-2023-38646")
        ),
        # solr
        os.path.normpath(
            os.path.abspath("./example/vulhub/solr/CVE-2017-12629-RCE")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/solr/CVE-2017-12629-XXE")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/solr/CVE-2019-0193")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/solr/CVE-2019-17558")
        ),
        # ofbiz
        os.path.normpath(
            os.path.abspath("./example/vulhub/ofbiz/CVE-2020-9496")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/ofbiz/CVE-2023-49070")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/ofbiz/CVE-2023-51467")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/ofbiz/CVE-2024-38856")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/ofbiz/CVE-2024-45195")
        ),
        os.path.normpath(
            os.path.abspath("./example/vulhub/ofbiz/CVE-2024-45507")
        ),
    }

    multi_jump_path = os.path.normpath(
        os.path.abspath("./example/multi-jump")
    )
    is_multi_jump = normalized_context_path == multi_jump_path
    is_single_scene = normalized_context_path in target_scene_paths

    if not (is_single_scene or is_multi_jump):
        return scene

    print("[Hook Java Apps]")

    if is_single_scene:
        # Single-scene mode: inject into service named "web"
        web_service = scene.services.get("web")
        if not web_service:
            return scene
        _inject_java_hook(web_service)
    
    elif is_multi_jump:
        # Multi-jump mode: only include services enabled in root multi-jump scene
        java_scene_tags = {
            "geoserver-cve-2024-36401",
            "geoserver/cve-2024-36401",
            "metabase-cve-2023-38646",
            "metabase/cve-2023-38646",
            "solr-cve-2019-17558",
            "solr/cve-2019-17558",
            "ofbiz-cve-2024-45507",
            "ofbiz/cve-2024-45507",
        }
        for service_name, service in scene.services.items():
            if not _is_web_service(service_name, service):
                continue
            if not _service_matches_scene_tags(service_name, service, java_scene_tags):
                continue
            print(f"  Injecting Java hook into service: {service_name}")
            _inject_java_hook(service)

    return scene


def hook_glibc_applog_trace(scene: Scene, cur_path: str) -> Scene:
    print("[Hook Glibc Applog & Trace]")
    exec_command(["/bin/bash", f"{cur_path}/hook_glibc_applog/build.sh"])
    exec_command(["/bin/bash", f"{cur_path}/hook_glibc_trace/build.sh"])
    # Shared attacker-side helper module. We mount it under a well-known
    # path in every service so that any scene's attack.py can do
    #   sys.path.insert(0, "/attacker_lib")
    #   from attack_markers import ATK_FLAG_2, with_form_field
    # without baking a per-scene copy. This file is a *method-layer*
    # helper: it never touches raw, never changes judgement, only provides
    # pure-string marker injection helpers (suffix/prefix/replace) for
    # form / query / header / path / filename / exec-arg positions.
    # Scenes choose strategy + field; everything else is owned here.
    attack_markers_path = f"{cur_path}/attack_markers.py"
    for service in scene.services.values():
        service.setdefault("volumes", []).append(
            f"{cur_path}/hook_glibc_applog/hook_glibc_applog.so:/hook_glibc_applog.so"
        )
        service.setdefault("volumes", []).append(
            f"{cur_path}/hook_glibc_trace/hook_glibc_trace.so:/hook_glibc_trace.so"
        )
        service["volumes"].append(
            f"{attack_markers_path}:/attacker_lib/attack_markers.py:ro"
        )
        envs: dict | list = service.get("environment", {})
        if isinstance(envs, list):
            envs.append({"LD_PRELOAD": "/hook_glibc_applog.so /hook_glibc_trace.so"})
            envs.append({"malicious": "false"})
        elif isinstance(envs, dict):
            envs["LD_PRELOAD"] = "/hook_glibc_applog.so /hook_glibc_trace.so"
            envs["malicious"] = "false"
        service["environment"] = envs
    return scene


def get_inv_dict(scene: Scene) -> dict[str, str]:
    print("[Get Inv Dict]")
    inv_dict: dict[str, str] = {}
    for service in scene.services.values():
        for _, network in service["networks"].items():
            original_ip = network["ipv4_address"]
            inv_ip = invert_ip(original_ip)
            inv_dict[original_ip] = inv_ip
    print(inv_dict)
    return inv_dict


def hook_glibc_attacker(scene: Scene, inv_dict: dict[str, str], cur_path: str) -> Scene:
    print("[Hook Glibc Attacker]")

    inv_dict_reverse = {v: k for k, v in inv_dict.items()}
    config_attack = f"ip_list = {inv_dict_reverse}\n"
    print(config_attack)

    with open(f"{cur_path}/hook_glibc_attacker/config_attack.py", "w") as f:
        f.write(config_attack)

    exec_command(["/bin/bash", f"{cur_path}/hook_glibc_attacker/build.sh"])
    for service in scene.services.values():
        service.setdefault("volumes", []).append(
            f"{cur_path}/hook_glibc_attacker/hook_glibc_attacker.so:/hook_glibc_attacker.so"
        )
    return scene


@contextmanager
def hook_kernel(scene: Scene, service_to_container_id: dict[str, str], cur_path: str):
    print("[Hook Kernel]")

    containers_have_applog = set()
    for service_name, cid in service_to_container_id.items():
        if "x-app-log" in scene.services[service_name]:
            containers_have_applog.add(cid)

    config_applog = f"container_names = {str(set(containers_have_applog))}\n\n"

    applog_path = {
        cid: scene.services[service_name]["x-app-log"]
        for service_name, cid in service_to_container_id.items()
        if "x-app-log" in scene.services[service_name]
    }
    config_applog += f"applog_path_prefixes = {applog_path}\n"

    print(config_applog)

    with open(f"{cur_path}/hook_kernel/config_applog.py", "w") as f:
        f.write(config_applog)

    exec_command(
        [
            "/bin/bash",
            "-c",
            f"cd {cur_path}/hook_kernel && (make INSTANCE=test clean || true)",
        ]
    )
    exec_command(
        ["/bin/bash", "-c", f"cd {cur_path}/hook_kernel && make INSTANCE=test"]
    )
    # Best-effort cleanup in case a previous run left the module loaded.
    exec_command(["sudo", "rmmod", "write_uuid_test"], check=False)
    exec_command(["sudo", "insmod", f"{cur_path}/hook_kernel/write_uuid_test.ko"])

    try:
        yield
    except BaseException as e:
        logger.exception(e)
        raise
    finally:
        exec_command(["sudo", "rmmod", "write_uuid_test"], check=False)


@contextmanager
def hook_netlog(
    service_to_container_id: dict[str, str],
    inv_dict: dict[str, str],
    cur_path: str,
):
    print("[Hook Netlog]")

    inv_dict_reverse = {v: k for k, v in inv_dict.items()}
    config_filter = f"hack_ips_orig = {inv_dict_reverse}\n\n"

    config_filter += (
        f"container_names = {str(set(service_to_container_id.values()))}\n\n"
    )

    print(config_filter)

    with open(f"{cur_path}/hook_netlog/config_filter.py", "w") as f:
        f.write(config_filter)

    exec_command(
        [
            "/bin/bash",
            "-c",
            f"cd {cur_path}/hook_netlog && (python_executable=$(which python) make INSTANCE=test clean || true)",
        ]
    )
    exec_command(
        [
            "/bin/bash",
            "-c",
            f"cd {cur_path}/hook_netlog && python_executable=$(which python) make INSTANCE=test",
        ]
    )
    # Best-effort cleanup in case a previous run left the module loaded.
    exec_command(["sudo", "rmmod", "filter_test"], check=False)
    exec_command(["sudo", "insmod", f"{cur_path}/hook_netlog/filter_test.ko"])

    try:
        yield
    except BaseException as e:
        logger.exception(e)
        raise
    finally:
        exec_command(["sudo", "rmmod", "filter_test"], check=False)


@contextmanager
def do_modify_pre(
    scene: Scene,
) -> Generator[tuple[Scene, dict[str, str], str], None, None]:
    print("[Do Modify Pre]")
    inv_dict = get_inv_dict(scene)
    with tempfile.TemporaryDirectory() as tmpdir:
        exec_command(["cp", "-r", "./modify", f"{tmpdir}/modify"])
        cur_path = f"{tmpdir}/modify"
        try:
            scene = hook_glibc_attacker(scene, inv_dict, cur_path)
            scene = hook_glibc_applog_trace(scene, cur_path)
            scene = hook_php_gitlist(scene, cur_path)
            scene = hook_java_apps(scene, cur_path)
            scene = add_app_log(scene)
            print(scene)
            # breakpoint()
        except BaseException as e:
            breakpoint()
            raise

        try:
            yield scene, inv_dict, cur_path
        except BaseException as e:
            logger.exception(e)
            raise


@contextmanager
def do_modify_after(
    scene: Scene,
    service_to_container_id: dict[str, str],
    inv_dict: dict[str, str],
    cur_path: str,
):
    print("[Do Modify After]")
    with hook_kernel(scene, service_to_container_id, cur_path):
        with hook_netlog(service_to_container_id, inv_dict, cur_path):
            try:
                yield
            except BaseException as e:
                logger.exception(e)
                raise
