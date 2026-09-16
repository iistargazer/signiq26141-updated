use quantum::{simulate_six_state_transmission, SiftedKeyResult};
use rand::Rng;

pub struct AttackSimulator;

impl AttackSimulator {
    pub fn run_intercept_resend_simulation(
        key: &[(quantum::PauliBasis, quantum::PauliState)],
        rng: &mut impl Rng,
    ) -> SiftedKeyResult {
        simulate_six_state_transmission(key, true, rng)
    }

    pub fn run_secure_simulation(
        key: &[(quantum::PauliBasis, quantum::PauliState)],
        rng: &mut impl Rng,
    ) -> SiftedKeyResult {
        simulate_six_state_transmission(key, false, rng)
    }
}
