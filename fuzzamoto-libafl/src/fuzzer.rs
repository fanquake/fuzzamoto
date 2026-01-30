use std::{cell::RefCell, fs::OpenOptions, io::Write, rc::Rc};

use clap::Parser;
use libafl::{
    Error,
    events::{ClientDescription, SimpleEventManager},
    monitors::{Monitor, tui::TuiMonitor},
};

#[cfg(not(feature = "simplemgr"))]
use libafl::events::{EventConfig, Launcher};

use libafl_bolts::{core_affinity::CoreId, current_time};

#[cfg(not(feature = "simplemgr"))]
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};

use crate::{
    client::Client,
    monitor::{self, GlobalMonitor},
    options::FuzzerOptions,
};

pub struct Fuzzer {
    options: FuzzerOptions,
}

impl Fuzzer {
    pub fn new() -> Fuzzer {
        let options = FuzzerOptions::parse();
        Fuzzer { options }
    }

    pub fn fuzz(&self) -> Result<(), Error> {
        if self.options.tui {
            let monitor = TuiMonitor::builder()
                .title("Fuzzamoto IR Fuzzer")
                .version("0.1.0")
                .enhanced_graphics(true)
                .build();
            self.launch(monitor)
        } else {
            let log = self.options.log.as_ref().and_then(|l| {
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(l)
                    .ok()
                    .map(RefCell::new)
                    .map(Rc::new)
            });

            let log_fn = {
                let log = log.clone();
                move |s: &str| {
                    println!("{s}");

                    if let Some(log) = &log {
                        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
                    }
                }
            };

            // The stats reporter for the broker
            let monitor = if let (Some(token), Some(user)) = (
                self.options.pushover_token.clone(),
                self.options.pushover_user.clone(),
            ) {
                println!("Using pushover notifications, will notify on first bug found");
                monitor::send_pushover_notification(&token, &user, "✅ New campaign has begun");
                GlobalMonitor::with_pushover(token, user, log_fn)
            } else {
                GlobalMonitor::new(log_fn)
            };
            self.launch(monitor)
        }
    }

    fn launch<M>(&self, monitor: M) -> Result<(), Error>
    where
        M: Monitor + Clone,
    {
        // The shared memory allocator
        #[cfg(not(feature = "simplemgr"))]
        let shmem_provider = StdShMemProvider::new()?;

        // If we are running in verbose, don't provide a replacement stdout, otherwise, use
        // /dev/null
        #[cfg(not(feature = "simplemgr"))]
        let stdout = if self.options.verbose {
            None
        } else {
            Some("/dev/null")
        };

        let client = Client::new(&self.options);

        #[cfg(not(feature = "simplemgr"))]
        if self.options.rerun_input.is_some() || self.options.minimize_input.is_some() {
            // To rerun an input, instead of using a launcher, we create dummy parameters and run
            // the client directly.
            return client.run(
                None,
                SimpleEventManager::new(monitor.clone()),
                ClientDescription::new(0, 0, CoreId(0)),
            );
        }

        #[cfg(feature = "simplemgr")]
        return client.run(
            None,
            SimpleEventManager::new(monitor),
            ClientDescription::new(0, 0, CoreId(0)),
        );

        // Build and run a Launcher
        #[cfg(not(feature = "simplemgr"))]
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(self.options.port)
            .configuration(EventConfig::from_build_id())
            // If starting with an existing corpus and many clients, crashes in the llmp broker
            // have been observed. Unclear what's happening, but an increased launch delay or fewer
            // clients mitigate the issue.
            .launch_delay(self.options.launch_delay)
            .monitor(monitor)
            .run_client(|s, m, c| client.run(s, m, c))
            .cores(&self.options.cores)
            .stdout_file(stdout)
            .stderr_file(stdout)
            .build()
            .launch()
        {
            Ok(()) => Ok(()),
            Err(Error::ShuttingDown) => {
                println!("Fuzzing stopped by user. Good bye.");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}
