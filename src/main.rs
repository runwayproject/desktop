use ratatui::{DefaultTerminal, Frame};
use ratatui::crossterm::event::{self, Event};
use std::io;
fn main() {
    let terminal = ratatui::init();
    let result = run(terminal);
    ratatui::restore();
}
fn run(mut terminal: DefaultTerminal) -> Result<(), io::Error> {
    loop {
        terminal.draw(render)?;
        if matches!(event::read()?, Event::Key(_)) {
            break Ok(());
        }
    }
}
fn render(frame: &mut Frame) {
    frame.render_widget("hello world", frame.area());
}
