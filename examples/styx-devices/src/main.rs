// SPDX-License-Identifier: BSD-2-Clause
use clap::Parser;

use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use styx_emulator::devices::{adc::ADS7866, dac::RHRDAC121, eeprom::AT25HP512};
use styx_emulator::peripheral_clients::spi::SPISimpleClient;

#[derive(Debug, Parser)]
#[command(name="emulator", version, about, long_about = None)]
struct ClientArgs {
    /// Port to connect to
    #[arg(short, long, default_value_t = 16000)]
    port: u16,

    /// Host to connect to
    #[arg(long, default_value_t = String::from("0.0.0.0"))]
    host: String,
}

impl ClientArgs {
    fn to_socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Display for ClientArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http://{}:{}", self.host, self.port)
    }
}

/*
use crossterm::{
    event::{self, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::widgets::{Block, Borders};
use ratatui::prelude::*;
use std::io::{stdout, Result};

struct App {
    messages: Vec<String>,
}

impl App {
    fn log_message(&mut self, message: String) {
        self.messages.push(message);
    }
    fn on_tick(&self) {

    }
}


fn render(frame: &mut Frame, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(frame.size());
    let sub_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    frame.render_widget(
        Block::new().borders(Borders::ALL).title("Events"),
        layout[0],
    );

    frame.render_widget(
        Block::new().borders(Borders::ALL).title("Input Signal"),
        sub_layout[0],
    );

    frame.render_widget(
        Block::new()
            .borders(Borders::ALL)
            .title("Output Signal"),
        sub_layout[1],
    );
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    tick_rate: Duration,
) -> Result<()> {
    let mut last_tick = Instant::now();
    loop {
        terminal.draw(|f| render(f, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    return Ok(());
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }
    }
}

fn main() -> Result<()> {
    stdout().execute(EnterAlternateScreen)?;
    enable_raw_mode()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;

    loop {
        //terminal.draw(|f| {render(f)})?;

        if event::poll(std::time::Duration::from_millis(16))? {
            if let event::Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    stdout().execute(LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}*/

// Wait for the emulator's IPC port to be up, then connect each device.
fn main() {
    let args = ClientArgs::parse();

    println!("waiting for {} ...", args.to_socket_addr());
    loop {
        thread::sleep(Duration::from_millis(100));
        match TcpStream::connect(args.to_socket_addr()) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }

    let eeprom = AT25HP512::new();
    let adc = ADS7866::new();
    let dac = RHRDAC121::new(None);

    let client0 = SPISimpleClient::new(args.to_string(), 0);
    client0.connect_device(eeprom);

    let client1 = SPISimpleClient::new(args.to_string(), 1);
    client1.connect_device(adc);

    let client2 = SPISimpleClient::new(args.to_string(), 2);
    client2.connect_device(dac);

    /*
    let _client_eeprom = SPIClient::new(args.to_string(), 0, eeprom);
    let _client_adc = SPIClient::new(args.to_string(), 1, adc);
    let _client_dac = SPIClient::new(args.to_string(), 2, dac);
    */

    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
