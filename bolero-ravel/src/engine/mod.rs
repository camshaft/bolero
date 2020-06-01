use bolero_engine::{panic as bolero_panic, DriverMode, Engine, Never, TargetLocation, Test};

mod callbacks;

#[derive(Debug, Default)]
pub struct RavelEngine {
    driver_mode: Option<DriverMode>,
}

impl RavelEngine {
    pub fn new(_location: TargetLocation) -> Self {
        Self::default()
    }
}

impl<T: Test> Engine<T> for RavelEngine {
    type Output = Never;

    fn set_driver_mode(&mut self, mode: DriverMode) {
        self.driver_mode = Some(mode);
    }

    fn run(self, _test: T) -> Self::Output {
        bolero_panic::set_hook();

        todo!()
    }
}
