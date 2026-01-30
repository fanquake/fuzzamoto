use crate::error::{CliError, Result};
use crate::utils::{file_ops, process};
use std::path::{Path, PathBuf};

pub struct CoverageCommand;

impl CoverageCommand {
    pub fn execute(
        output: &Path,
        corpus: &Path,
        bitcoind: &Path,
        scenario: &Path,
        profraws: Option<Vec<PathBuf>>,
        run_only: bool,
    ) -> Result<()> {
        file_ops::ensure_file_exists(bitcoind)?;
        file_ops::ensure_file_exists(scenario)?;

        if run_only {
            let corpus_files = file_ops::read_dir_files(corpus)?;
            for corpus_file in corpus_files {
                if let Err(e) = Self::run_one_input(output, &corpus_file, bitcoind, scenario) {
                    log::error!("Failed to run input ({:?}): {e}", corpus_file.display());
                }
            }
            return Ok(());
        }

        let profdata = if let Some(profraws) = profraws {
            let profraws: Vec<&Path> = profraws.iter().map(PathBuf::as_path).collect();
            Self::merge_profraws(output, &profraws)?
        } else {
            let corpus_files = file_ops::read_dir_files(corpus)?;
            log::info!("{corpus_files:?}");
            // Run scenario for each corpus file
            for corpus_file in corpus_files {
                if let Err(e) = Self::run_one_input(output, &corpus_file, bitcoind, scenario) {
                    log::error!("Failed to run input ({:?}): {e}", corpus_file.display());
                }
            }

            let profraws_dir = vec![output];
            Self::merge_profraws(output, &profraws_dir)?
        };

        Self::generate_report(output, bitcoind, &profdata)?;
        Ok(())
    }

    fn run_one_input(output: &Path, input: &Path, bitcoind: &Path, scenario: &Path) -> Result<()> {
        log::info!("Running scenario with input: {}", input.display());

        let profraw_file = output.join(format!(
            "{}.coverage.profraw.%p",
            input.file_name().unwrap().to_str().unwrap()
        ));

        let env_vars = vec![
            ("LLVM_PROFILE_FILE", profraw_file.to_str().unwrap()),
            ("FUZZAMOTO_INPUT", input.to_str().unwrap()),
            ("RUST_LOG", "debug"),
        ];

        process::run_scenario_command(scenario, bitcoind, &env_vars)?;

        Ok(())
    }

    fn generate_report(output: &Path, bitcoind: &Path, coverage_profdata: &Path) -> Result<()> {
        // Generate HTML report
        let coverage_report_dir = output.join("coverage-report");
        let coverage_report_str = coverage_report_dir.to_str().unwrap();
        let instr_profile_arg = format!("-instr-profile={}", coverage_profdata.to_str().unwrap());
        let output_dir_arg = format!("-output-dir={coverage_report_str}");

        let show_args = vec![
            "show",
            bitcoind.to_str().unwrap(),
            &instr_profile_arg,
            "-format=html",
            "-show-directory-coverage",
            "-show-branches=count",
            &output_dir_arg,
            "-Xdemangler=c++filt",
        ];

        let show_cmd = process::get_llvm_command("llvm-cov");
        process::run_command_with_status(&show_cmd, &show_args, None)?;

        log::info!(
            "Coverage report generated in: {}",
            coverage_report_dir.display()
        );

        Ok(())
    }

    fn merge_profraws(output: &Path, profraws: &Vec<&Path>) -> Result<PathBuf> {
        if profraws.is_empty() {
            return Err(CliError::InvalidInput(
                "No profraws directory provided".to_string(),
            ));
        }

        let mut profraw_files = Vec::new();

        for p in profraws {
            for entry in std::fs::read_dir(p)? {
                let path = entry?.path();
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str())
                    && file_name.contains("coverage.profraw")
                {
                    profraw_files.push(path.to_str().unwrap().to_string());
                }
            }
        }

        if profraw_files.is_empty() {
            return Err(CliError::ProcessError("No profraw files found".to_string()));
        }

        let merged = output.join("coverage.profdata");
        let mut merge_args = vec!["merge", "-sparse"];

        let inputs: Vec<&str> = profraw_files
            .iter()
            .map(std::string::String::as_str)
            .collect();
        log::info!("Merging profdata from {inputs:?}");

        merge_args.extend(inputs);
        merge_args.extend(["-o", merged.to_str().unwrap()]);
        let merge_cmd = process::get_llvm_command("llvm-profdata");
        process::run_command_with_status(&merge_cmd, &merge_args, None)?;

        Ok(merged)
    }
}
