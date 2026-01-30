use libafl::{
    Error,
    corpus::{CachedOnDiskCorpus, OnDiskCorpus},
    events::{
        ClientDescription, EventFirer, EventReceiver, EventRestarter, ProgressReporter, SendExiting,
    },
    state::StdState,
};
use libafl_bolts::rands::StdRand;

use crate::{input::IrInput, instance::Instance, options::FuzzerOptions};

pub type ClientState =
    StdState<CachedOnDiskCorpus<IrInput>, IrInput, StdRand, OnDiskCorpus<IrInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl<'a> Client<'a> {
    pub fn new(options: &'a FuzzerOptions) -> Self {
        Self { options }
    }

    pub fn run<EM>(
        &self,
        state: Option<ClientState>,
        mgr: EM,
        client_description: ClientDescription,
    ) -> Result<(), Error>
    where
        EM: EventFirer<IrInput, ClientState>
            + EventRestarter<ClientState>
            + ProgressReporter<ClientState>
            + SendExiting
            + EventReceiver<IrInput, ClientState>,
    {
        let instance = Instance::builder()
            .options(self.options)
            .mgr(mgr)
            .client_description(client_description);

        instance.build().run(state)
    }
}
