pub fn app_name() -> &'static str {
    if cfg!(debug_assertions) {
        "DustonicDev"
    } else {
        "Dustonic"
    }
}
