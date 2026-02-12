use eframe::egui;
use crate::mls::create_credentials_openmls;

mod mls;
struct Asphalt {
    show_first_launch: bool,
    mls_created: bool,
}

impl Default for Asphalt {
    fn default() -> Self {
        Self {
            show_first_launch: true,
            mls_created: false,
        }
    }
}

impl eframe::App for Asphalt {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.show_first_launch {
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.heading("First launch");
                    ui.add_space(6.0);
                    ui.label("This is the first launch of Asphalt.");
                    ui.add_space(8.0);
                    if ui.button("Create MLS credentials").clicked() {
                        create_credentials_openmls();
                        self.mls_created = true;
                        self.show_first_launch = false;
                    }
                });
            } else {
                ui.heading("Hello, World!");
                if self.mls_created {
                    ui.label("MLS credentials created.");
                } else {
                    ui.label("MLS credentials not created.");
                }
            }
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default(); 
    eframe::run_native("Asphalt", options, Box::new(|_cc| Ok(Box::new(Asphalt::default()) as Box<dyn eframe::App>)))?;
    Ok(())
}