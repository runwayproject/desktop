use eframe::egui;
#[derive(Default)]
struct Asphalt {

}

impl eframe::App for Asphalt {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Hello, World!");
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default(); 
    eframe::run_native("Asphalt", options, Box::new(|_cc| Ok(Box::new(Asphalt::default()) as Box<dyn eframe::App>)))?;
    Ok(())
}