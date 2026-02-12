use eframe::egui;
use crate::mls::create_credentials_openmls;

mod mls;
struct Asphalt {
    show_first_launch: bool,
    mls_created: bool,
    messages: Vec<(String, String)>,
    input: String,
}

impl Default for Asphalt {
    fn default() -> Self {
        Self {
            show_first_launch: true,
            mls_created: false,
            messages: Vec::new(),
            input: String::new(),
        }
    }
}

impl Asphalt {
    fn first_launch_ui(&mut self, ui: &mut egui::Ui) {
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
    }
    fn chat_ui(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(8.0);
            ui.heading("Chat");
            ui.add_space(6.0);

            if self.mls_created {
                ui.label("MLS credentials created.");
            } else {
                ui.label("MLS credentials not created.");
            }
            ui.add_space(6.0);

            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                for (sender, text) in &self.messages {
                    ui.horizontal(|ui| {
                        ui.label(format!("{}:", sender));
                        ui.label(text);
                    });
                    ui.separator();
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let text_edit = ui.text_edit_singleline(&mut self.input);
                let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Send").clicked() || (text_edit.lost_focus() && enter_pressed) {
                    if !self.input.trim().is_empty() {
                        self.messages.push(("You".to_owned(), self.input.trim().to_owned()));
                        self.input.clear();
                    }
                }
            });
            ui.add_space(8.0);
        });
    }
}

impl eframe::App for Asphalt {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.show_first_launch {
                self.first_launch_ui(ui);
            } else {
                self.chat_ui(ui);
            }
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default(); 
    eframe::run_native("Asphalt", options, Box::new(|_cc| Ok(Box::new(Asphalt::default()) as Box<dyn eframe::App>)))?;
    Ok(())
}