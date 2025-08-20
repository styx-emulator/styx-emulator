// SPDX-License-Identifier: BSD-2-Clause
//! TUI for ppc405 freertos demo.
//!
//! Press space to sent a uart character, press q to quit.
//!
//! Tests are checked at tick 3000 in the firmware. The uart test passes if A-Z is sent before the
//! tests are evaluated. All other tests should pass with no user input required.
//!
//! Known Bugs: Occasionally the space to send a uart character freezes everything.
//!
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style, Stylize};
use ratatui::widgets::Wrap;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    symbols::border,
    text::{Line, Text},
    widgets::{Block, Paragraph, Widget},
    DefaultTerminal, Frame,
};
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use styx_emulator::core::executor::DefaultExecutor;
use tracing::info;
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerWidget};

use styx_emulator::arch::ppc32::Ppc32Register;
use styx_emulator::core::util::resolve_test_bin;
use styx_emulator::peripheral_clients::uart::UartClient;
use styx_emulator::prelude::*;
use styx_emulator::processors::ppc::ppc4xx::PowerPC405Builder;

pub mod ppc32_prelude {
    pub use styx_emulator::arch::ppc32::Ppc32Register as Reg;
}

const FREERTOS_PATH: &str = "ppc/ppc405/bin/freertos_ethernet.bin";

pub trait Cpu32Bit {
    /// Read a 32 bit register, unwraps.
    fn read_reg(&mut self, register: impl Into<ArchRegister>) -> u32;
    /// Writes a 32 bit register, unwraps.
    fn write_reg(&mut self, register: impl Into<ArchRegister>, value: u32);
}

impl Cpu32Bit for &mut dyn CpuBackend {
    fn read_reg(&mut self, register: impl Into<ArchRegister>) -> u32 {
        self.read_register::<u32>(register).unwrap()
    }

    fn write_reg(&mut self, register: impl Into<ArchRegister>, value: u32) {
        self.write_register(register, value).unwrap()
    }
}

fn freertos_builder() -> ProcessorBuilder<'static> {
    let test_bin_path = resolve_test_bin(FREERTOS_PATH);
    let loader_yaml = format!(
        r#"
        - !FileRaw
            base: 0xfff00000
            file: {test_bin_path}
            perms: !AllowAll
        - !RegisterImmediate
            register: pc
            value: 0xfffffffc
"#
    );
    ProcessorBuilder::default()
        .with_builder(PowerPC405Builder::default())
        .with_loader(ParameterizedLoader::default())
        .with_input_bytes(loader_yaml.as_bytes().to_vec().into())
        .with_executor(DefaultExecutor)
        .with_ipc_port(IPCPort::any())
}

/// Tracks test status.
#[derive(Debug)]
struct Test {
    name: String,
    status: TestStatus,
}

impl Default for TestStatus {
    /// Returns the default value of `TestStatus`, which is `Nothing`.
    fn default() -> Self {
        Self::Nothing
    }
}

/// Represents the current status of a test.
#[derive(Debug)]
enum TestStatus {
    Failure,
    Nothing,
    Success,
}

impl Test {
    /// Monitors the execution of a specific task by checking the value in register R3.
    /// If the value is 1, the test succeeds; otherwise, it fails.
    fn new_hook(name: &'static str, addr: u64, backend: &SyncProcessor) -> Arc<Mutex<Test>> {
        Self::new_hook_reg(name, addr, backend, Ppc32Register::R3, 1)
    }
    /// Monitors the execution of a specific task by checking the value in `reg`.
    /// If the value is `test_value`, the test succeeds; otherwise, it fails.
    fn new_hook_reg(
        name: &'static str,
        addr: u64,
        backend: &SyncProcessor,
        reg: Ppc32Register,
        test_value: u32,
    ) -> Arc<Mutex<Test>> {
        let test = Arc::new(Mutex::new(Self {
            name: name.to_owned(),
            status: Default::default(),
        }));
        {
            let test = test.clone();
            backend
                .add_hook(StyxHook::code(addr, move |mut proc: CoreHandle| {
                    let r3 = proc.cpu.read_reg(reg);
                    if r3 == test_value {
                        test.lock().unwrap().succeed();
                    } else {
                        test.lock().unwrap().fail();
                    }
                    Ok(())
                }))
                .unwrap();
        }

        test
    }

    /// Moves the test's status to `Success` unless a failure has occurred.
    fn succeed(&mut self) {
        let name = &self.name;
        self.status = match self.status {
            TestStatus::Nothing => {
                tracing::info!("{name} succeeded");
                TestStatus::Success
            }
            TestStatus::Success => TestStatus::Success,
            TestStatus::Failure => TestStatus::Failure,
        };
    }

    /// Moves the test's status to `Failure`.
    fn fail(&mut self) {
        let name = &self.name;
        self.status = match self.status {
            TestStatus::Nothing | TestStatus::Success => {
                tracing::info!("{name} failed");
                TestStatus::Failure
            }
            TestStatus::Failure => TestStatus::Failure,
        };
    }

    /// Returns a string representation of the test's status.
    fn status_styled(&self) -> ratatui::prelude::Span<'static> {
        match self.status {
            TestStatus::Success => "succeeded".green(),
            TestStatus::Failure => "failed".red(),
            TestStatus::Nothing => "not checked".gray(),
        }
    }
}
#[derive(Default, Debug)]
/// Struct to manage a collection of tests.
pub struct Tests {
    /// Vector containing references to all added tests.
    tests: Vec<Arc<Mutex<Test>>>,
}

impl Tests {
    /// Adds a new test to the manager.
    ///
    /// Returns A mutable reference to the updated `Tests` instance.
    fn add(&mut self, test: Arc<Mutex<Test>>) -> &mut Self {
        self.tests.push(test);
        self
    }
}

#[derive(Clone, Debug, Default)]
struct LastTest {
    last: Arc<Mutex<Option<Instant>>>,
}

impl LastTest {
    fn update(&self) {
        let mut last = self.last.lock().unwrap();
        *last = Some(Instant::now());
    }

    fn time_since(&self) -> Option<Duration> {
        self.last.lock().unwrap().map(|last| Instant::now() - last)
    }

    fn format(&self) -> Line {
        let time_str = match self.time_since() {
            Some(time) => format!("{} seconds", time.as_secs()).yellow(),
            None => "never".red(),
        };

        vec!["Time Since Last Test: ".into(), time_str].into()
    }
}

#[derive(Debug)]
struct Task {
    name: String,
    prio: u32,
}

impl Task {
    fn from_addr(core: &SyncProcessor, addr: u64) -> Option<Self> {
        let name = read_string_from_memory(core, addr + 0x34)?;
        let prio = core.data().read(addr + 0x4c).be().u32().unwrap();
        Some(Self { name, prio })
    }
}
/// Assumes the existence of a null terminated, C style string starting at the address provided.
/// There is no checking to see if bytes form valid utf8 characters.
fn read_string_from_memory(mmu: &SyncProcessor, address: u64) -> Option<String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(32);

    let mut n = 0;
    let mut buf = [0u8; 1];
    loop {
        mmu.data().read(address + n).bytes(&mut buf).unwrap();
        buffer.push(buf[0]);
        if buf[0] == 0 {
            break;
        }
        buf[0] = 0;
        n += 1;
    }

    String::from_utf8(buffer).ok()
}

/// Tests system using a build of FreeRTOS.
///
/// Currently checks for success in the math task and that the LED task gets
/// scheduled after its delay.
///
fn main() {
    tui_logger::init_logger(tui_logger::LevelFilter::Info).unwrap();
    tui_logger::set_default_level(tui_logger::LevelFilter::Info);

    let builder = freertos_builder();

    let processor = builder.build_sync().unwrap();
    info!("built processor");

    let mut tests = Tests::default();
    tests
        .add(Test::new_hook("Math", 0xfff0260c, &processor))
        .add(Test::new_hook("Coms (UART)", 0xfff02624, &processor))
        .add(Test::new_hook("Semaphore", 0xfff0263c, &processor))
        .add(Test::new_hook("Blocking Queues", 0xfff02654, &processor))
        .add(Test::new_hook(
            "Dynamic Priority Tasks",
            0xfff0266c,
            &processor,
        ))
        .add(Test::new_hook("Create Task", 0xfff02684, &processor))
        .add(Test::new_hook("Block Time", 0xfff0269c, &processor))
        .add(Test::new_hook("Generic Queues", 0xfff026b4, &processor))
        .add(Test::new_hook("Queue Peek", 0xfff026cc, &processor))
        .add(Test::new_hook("Counting Semaphore", 0xfff026e4, &processor))
        .add(Test::new_hook("Recursive Mutex", 0xfff026fc, &processor))
        .add(Test::new_hook_reg(
            "Reg Test Status",
            0xfff02718,
            &processor,
            Ppc32Register::R0,
            1,
        ))
        .add(Test::new_hook("Complete Tests", 0xfff027ac, &processor));

    info!("hooks added");

    info!("processor started");

    let mut terminal = ratatui::init();
    let mut app = App::new(processor, tests);
    let app_result = app.run(&mut terminal);
    ratatui::restore();
    app_result.unwrap();
}

struct UartControl {
    uart_client: Arc<Mutex<UartClient>>,
    /// Infinitely looping ascii A-X iterator
    letters_iter: Box<dyn Iterator<Item = u8>>,
}

impl UartControl {
    fn new(processor: &SyncProcessor) -> Self {
        let ipc_port = processor.ipc_port();
        info!("Trying to connect...");
        loop {
            match TcpStream::connect(format!("127.0.0.1:{ipc_port}")) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        let uart = UartClient::new(format!("http://127.0.0.1:{ipc_port}"), Some(0));
        let uart = Arc::new(Mutex::new(uart));

        info!("Connected!...");

        let letters_iter = Box::new(('A'..='X').cycle().map(|c| c as u8));

        Self {
            uart_client: uart,
            letters_iter,
        }
    }

    /// Space pressed, send letters
    fn next(&mut self) {
        self.one_at_a_time();
    }

    /// Send a letter, one at a time.
    fn one_at_a_time(&mut self) {
        let next_letter = self.letters_iter.next().unwrap();
        self.uart_client.lock().unwrap().send(vec![next_letter]);
    }
}
pub struct App {
    proc: SyncProcessor,
    proc_status: ProcStatus,
    tests_status: TestsStatus,
    uart_status: UartStatus,
    uart: UartControl,
    exit: bool,
}

impl App {
    pub fn new(proc: SyncProcessor, tests: Tests) -> Self {
        let uart = UartControl::new(&proc);
        let tests_status = TestsStatus::new(&proc, tests);
        let uart_status = UartStatus::new(&proc);
        Self {
            proc_status: ProcStatus::new(&proc),
            proc,
            tests_status,
            uart_status,
            uart,
            exit: false,
        }
    }
    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        self.proc.start(Forever).unwrap();
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;
            self.handle_events()?;
        }

        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }

    /// updates the application's state based on user input
    fn handle_events(&mut self) -> io::Result<()> {
        let event_available = event::poll(Duration::from_millis(1000))?;
        if event_available {
            match event::read()? {
                // it's important to check that the event is a key press event as
                // crossterm also emits key release and repeat events on Windows.
                Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                    self.handle_key_event(key_event)
                }
                _ => {}
            };
        }

        Ok(())
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('q') => self.exit(),
            KeyCode::Char(' ') => self.uart.next(),
            _ => {}
        }
    }

    fn exit(&mut self) {
        self.exit = true;
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let layout = Layout::default()
            .direction(ratatui::layout::Direction::Horizontal)
            .constraints(vec![Constraint::Length(45), Constraint::Fill(1)])
            .split(area);

        let left_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Percentage(25),
                Constraint::Percentage(50),
                Constraint::Percentage(25),
            ])
            .split(layout[0]);

        self.proc_status.render(left_layout[0], buf);
        LogWidget.render(layout[1], buf);
        self.tests_status.render(left_layout[1], buf);
        self.uart_status.render(left_layout[2], buf);
    }
}

#[derive(Debug)]
pub struct LogWidget;
impl Widget for LogWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Line::from(" Logs ".bold());
        let block = Block::bordered()
            .title(title.centered())
            .border_set(border::THICK);
        TuiLoggerWidget::default()
            .block(block)
            .style_error(Style::default().fg(Color::Red))
            .style_debug(Style::default().fg(Color::Green))
            .style_warn(Style::default().fg(Color::Yellow))
            .style_trace(Style::default().fg(Color::Magenta))
            .style_info(Style::default().fg(Color::Cyan))
            .output_separator(':')
            .output_timestamp(Some("%H:%M:%S".to_string()))
            .output_level(Some(TuiLoggerLevelOutput::Abbreviated))
            .output_target(true)
            .output_file(true)
            .output_line(true)
            .render(area, buf);
    }
}

#[derive(Debug)]
pub struct ProcStatus {
    proc: SyncProcessor,
}

impl ProcStatus {
    fn new(proc: &SyncProcessor) -> Self {
        Self { proc: proc.clone() }
    }

    fn get_task(core: &SyncProcessor) -> Option<Task> {
        let new_handle = core.data().read(0xfff1212cu64).be().u32().unwrap();

        Task::from_addr(core, new_handle as u64)
    }
}

impl Widget for &ProcStatus {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Line::from(" Processor Status ".bold());

        let block = Block::bordered()
            .title(title.centered())
            .border_set(border::THICK);

        let pc = self.proc.pc().unwrap();
        let current_tick = self.proc.data().read(0xfff12138u64).be().u32().unwrap();
        let next_task_unblock_time = self.proc.data().read(0xfff12154u64).be().u32().unwrap();

        let this_task = ProcStatus::get_task(&self.proc);

        let this_task_name = this_task
            .as_ref()
            .map(|a| a.name.clone())
            .unwrap_or("Task NA".to_owned());
        let this_task_prio = this_task
            .map(|a| a.prio.to_string())
            .unwrap_or("NA".to_owned());

        let status_text = Text::from(vec![
            Line::from(vec!["PC: ".into(), format!("0x{pc:X}").yellow()]),
            Line::from(vec![
                "Current Tick: ".into(),
                current_tick.to_string().yellow(),
                " | Next Task Switch ".into(),
                next_task_unblock_time.to_string().yellow(),
            ]),
            Line::from(vec![
                "Current Task (priority): ".into(),
                format!("{this_task_name} ({this_task_prio})").yellow(),
            ]),
        ]);

        Paragraph::new(status_text)
            .left_aligned()
            .block(block)
            .render(area, buf);
    }
}

#[derive(Debug)]
pub struct TestsStatus {
    tests: Tests,
    last: LastTest,
}

impl TestsStatus {
    fn new(proc: &SyncProcessor, tests: Tests) -> Self {
        let last = LastTest::default();

        {
            let last = last.clone();
            proc.add_hook(StyxHook::code(0xfff025ec, move |_core: CoreHandle<'_>| {
                info!("Performing whole system check");
                last.update();
                Ok(())
            }))
            .unwrap();
        }
        Self { tests, last }
    }
}

impl Widget for &TestsStatus {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Line::from(" Tests Status ".bold());
        let block = Block::bordered()
            .title(title.centered())
            .border_set(border::THICK);

        let tests = self.tests.tests.iter().map(|a| {
            let test = a.lock().unwrap();
            Line::from(vec![
                test.name.clone().into(),
                " ".into(),
                test.status_styled(),
            ])
        });

        let mut status_text = Text::from_iter(tests);
        status_text.push_line(self.last.format());

        Paragraph::new(status_text)
            .left_aligned()
            .block(block)
            .render(area, buf);
    }
}

#[derive(Debug)]
pub struct UartStatus {
    proc: SyncProcessor,
    bytes_rx: Arc<Mutex<Vec<u8>>>,
}

impl UartStatus {
    fn new(proc: &SyncProcessor) -> Self {
        let bytes_rx: Arc<Mutex<Vec<u8>>> = Default::default();
        {
            let bytes_rx = bytes_rx.clone();
            proc.add_hook(StyxHook::code(0xfff0302c, move |mut proc: CoreHandle| {
                let r4 = proc.cpu.read_reg(Ppc32Register::R4);
                let r4 = proc.mmu.data().read(r4).u8().unwrap();
                if r4 != 0 {
                    info!("call to xQueueGenericSendFromISR -> read char: 0x{r4:X}");
                    bytes_rx.lock().unwrap().push(r4);
                }
                Ok(())
            }))
            .unwrap();
        }

        Self {
            proc: proc.clone(),
            bytes_rx,
        }
    }
}

impl Widget for &UartStatus {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Line::from(" Uart Status ".bold());

        let block = Block::bordered()
            .title(title.centered())
            .border_set(border::THICK);

        let bytes_rx = self.bytes_rx.lock().unwrap();
        let num_bytes = bytes_rx.len();
        let bytes_str = bytes_rx
            .iter()
            .map(|b| match char::from_u32(*b as u32).unwrap() {
                '\0' => 'X',
                x => x,
            })
            .collect::<String>();

        let rx_recv = self.proc.data().read(0xfff1205cu64).vec(4).unwrap()[3];
        // uxRxLoops

        let status_text = Text::from(vec![
            Line::from(vec![
                "# bytes received: ".into(),
                num_bytes.to_string().yellow(),
            ]),
            Line::from(vec![
                "Current Loop Count: ".into(),
                rx_recv.to_string().yellow(),
            ]),
            Line::from(vec!["Text received: ".into()]),
            Line::from(vec![bytes_str.into()]),
        ]);

        Paragraph::new(status_text)
            .left_aligned()
            .wrap(Wrap { trim: true })
            .block(block)
            .render(area, buf);
    }
}
