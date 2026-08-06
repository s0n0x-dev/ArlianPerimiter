// build.rs — запускается cargo перед компиляцией
// Автоматически устанавливает BUILD_DATE если не задан вручную

fn main() {
    // Если BUILD_DATE не передан снаружи — берём текущую дату
    if std::env::var("BUILD_DATE").is_err() {
        let date = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
        println!("cargo:rustc-env=BUILD_DATE={}", date);
    }

    // Говорим cargo пересобрать если build.rs изменился
    println!("cargo:rerun-if-changed=build.rs");
}
