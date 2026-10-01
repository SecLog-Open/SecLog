import os

import signal
import time

import click
import psutil
import typer
from loguru import logger
from rich import print

from analyze import analyze_logs
from console_observability import StageTimer, path_exists
from logs import assert_logging_healthy, stop_logging_watchdog
from parse import parse_config
from scene import start_scene, stop_scene
from utils import ensure_sudo_session, exec_command, stop_sudo_session


def main(
    config_path: str = typer.Option(help="Path to the configuration folder"),
    output_path: str = typer.Option("results", help="Path to the output folder"),
    export_attack_chains: bool = typer.Option(
        True,
        "--export-attack-chains/--no-export-attack-chains",
        help="Keep the legacy attack_chains compatibility path; enabled by default, but the Mode B path does not run or write attack_chains.jsonl by default",
    ),
    export_replay_index: bool = typer.Option(
        True,
        "--export-replay-index/--no-export-replay-index",
        help="Keep the legacy replay/event_index compatibility path; enabled by default, but the Mode B path does not write event_index or node_index by default",
    ),
    chain_mode: str = typer.Option(
        "unit",
        help="Chain partition mode: unit=per session or Unit, cc=connected components",
    ),
    max_normal_chains: int | None = typer.Option(
        0,
        help="Maximum number of normal chains to keep (default 0, export attack chains only)",
    ),
    normal_sample_ratio: float | None = typer.Option(
        0,
        help="Normal-chain sampling ratio from 0 to 1 (default 0, disabled)",
    ),
    mode_b_dataset: bool = typer.Option(
        True,  # Use the separate raw/index format by default.
        "--mode-b/--no-mode-b",
        help="Mode B: generate the full-text attack-chain dataset with separate raw and index data; enabled by default",
    ),
    event_index_batch_size: int | None = typer.Option(
        None,
        help="Batch write size for the legacy event_index export only; ignored by the Mode B path",
    ),
    skip_validation: bool = typer.Option(
        True,
        "--skip-validation/--no-skip-validation",
        help="Skip validation (useful for batch dataset generation; enabled by default)",
    ),
    export_applog_backbone_candidates: bool = typer.Option(
        False,
        "--export-applog-backbone-candidates/--no-export-applog-backbone-candidates",
        help="Also export applog_backbone_candidate_index; disabled by default",
    ),
    export_applog_write_level_labels: bool = typer.Option(
        False,
        "--export-applog-write-level-labels/--no-export-applog-write-level-labels",
        help=(
            "Write the applog_write_level_labels.v0.jsonl diagnostic sidecar. "
            "Disabled by default; this write-gated labeling evidence is consumed only by QA and replay scripts "
            "under scripts/ and is not part of the backbone, dataset, or release. "
            "Enable it when investigating why an applog entry was labeled strong, weak, or none."
        ),
    ),
):
    ensure_sudo_session()
    print("SecLog is Starting.")

    try:
        parse_stage = StageTimer(
            "parse_config",
            prefix="[main][stage]",
            emit_fn=logger.info,
            base_fields={"input_path": config_path, "output_path": output_path},
        )
        parse_stage.start(config_exists=path_exists(config_path))
        scene = parse_config(config_path)
        scene_name = os.path.basename(os.path.normpath(config_path)) or "scene"
        parse_stage.done(scene_name=scene_name)
        logger.info(f"Parsed config for scene: {scene_name}")
        
        scene_stage = StageTimer(
            "scene_execution",
            prefix="[main][stage]",
            emit_fn=logger.info,
            base_fields={"scenario_dir": scene_name, "input_path": config_path, "output_path": output_path},
        )
        scene_stage.start(config_exists=path_exists(config_path))
        service_to_container_id, inv_dict = start_scene(scene)
        assert_logging_healthy()
        scene_stage.done(container_count=len(service_to_container_id), inv_dict_count=len(inv_dict))
        logger.info(f"Scene started, containers: {len(service_to_container_id)}")
        
        # Confirm that the scene started successfully.
        if not service_to_container_id:
            logger.error("Scene failed to start - no containers were created. Cannot proceed with analysis.")
            raise RuntimeError("Scene failed to start. Docker build or container startup failed.")
        
        stop_stage = StageTimer(
            "stop_scene",
            prefix="[main][stage]",
            emit_fn=logger.info,
            base_fields={"scenario_dir": scene_name, "output_path": output_path},
        )
        stop_stage.start(container_count=len(service_to_container_id))
        stop_all()
        stop_stage.done()
        logger.info("Scene stopped, waiting for logs to be saved...")

        print("Sleeping for 10 seconds to wait for the logs to be saved...")
        time.sleep(10)
        
        # Create the output directory before writing results.
        os.makedirs(output_path, exist_ok=True)
        logger.info(f"Output directory ensured: {output_path}")
        
        analyze_stage = StageTimer(
            "analyze_logs",
            prefix="[main][stage]",
            emit_fn=logger.info,
            base_fields={"scenario_dir": scene_name, "input_path": config_path, "output_path": output_path},
        )
        analyze_stage.start(output_root_exists=path_exists(output_path))
        analyze_logs(
            scene,
            service_to_container_id,
            inv_dict,
            output_path,
            scene_name=scene_name,
            export_attack_chains_flag=export_attack_chains,
            export_replay_index_flag=export_replay_index,
            chain_mode=chain_mode,
            max_normal_chains=max_normal_chains,
            normal_sample_ratio=normal_sample_ratio,
            mode_b_dataset=mode_b_dataset,
            event_index_batch_size=event_index_batch_size,
            skip_validation=skip_validation,
            export_applog_backbone_candidates=export_applog_backbone_candidates,
            export_applog_write_level_labels=export_applog_write_level_labels,
        )
        analyze_stage.done(output_root_exists=path_exists(output_path))
        logger.info(f"analyze_logs completed successfully for {scene_name}")
    except Exception as e:
        logger.info(
            f"[main][stage] stage=main status=failed input_path={config_path} output_path={output_path} error={e}"
        )
        logger.exception(f"Error in main function: {e}")
        raise


def stop_all():
    stop_logging_watchdog()
    stop_scene()

    parent = psutil.Process(os.getpid())
    children = parent.children(recursive=True)

    for child in children:
        print(f"Terminating child process {child.pid}...")
        try:
            exec_command(["sudo", "kill", str(child.pid)])
        except Exception as e:
            logger.warning(e)

    gone, still_alive = psutil.wait_procs(children, timeout=5)

    for child in still_alive:
        print(f"Child process {child.pid} did not terminate, killing it...")
        try:
            exec_command(["sudo", "kill", "-9", str(child.pid)])
        except Exception as e:
            logger.warning(e)


def stop_handler(signum, frame):
    raise SystemExit(1)


def add_stop_handler():
    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)


if __name__ == "__main__":
    add_stop_handler()
    exit_code = 0

    try:
        typer.run(main)
    except SystemExit as e:
        if e.code is None:
            exit_code = 0
        elif isinstance(e.code, int):
            exit_code = e.code
        else:
            exit_code = 1
        print(f"Exited with code {e.code}.")
    except BaseException as e:
        logger.exception(e)
        exit_code = 1
    finally:
        print("SecLog is Stopping.")
        try:
            stop_all()
        except BaseException as e:
            logger.exception(e)
            if exit_code == 0:
                exit_code = 1
        finally:
            stop_sudo_session()

    raise SystemExit(exit_code)
