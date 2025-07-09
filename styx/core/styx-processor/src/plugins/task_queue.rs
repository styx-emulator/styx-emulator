// SPDX-License-Identifier: BSD-2-Clause
use std::{
    collections::VecDeque,
    fmt::Debug,
    sync::{mpsc, Arc, Mutex},
};

use log::trace;
use styx_errors::UnknownError;

use crate::core::ProcessorCore;

use super::{Plugin, UninitPlugin};

pub struct TaskHandle<T> {
    recv: mpsc::Receiver<T>,
}

impl<T> TaskHandle<T> {
    /// Block until the task is run and return the result of the task.
    pub fn join(self) -> T {
        self.recv.recv().unwrap()
    }
}

struct Task {
    function: Box<dyn FnOnce(&mut ProcessorCore) + Send>,
}

/// Add tasks to the queue. Freely cloneable.
#[derive(Clone)]
pub struct TaskQueueHandle {
    tasks: Arc<Mutex<VecDeque<Task>>>,
}
impl Debug for TaskQueueHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskQueue").finish()
    }
}
impl TaskQueueHandle {
    /// Add a task to the queue. The task will be run on the next processor tick.
    ///
    /// [`TaskHandle::join()`] allows you to get the returned value and block until the task is
    /// completed. However, the task will run and complete even if not joined.
    pub fn add_task<T: Send + 'static>(
        &self,
        task: impl FnOnce(&mut ProcessorCore) -> T + Send + 'static,
    ) -> TaskHandle<T> {
        let (send, recv) = mpsc::channel();
        let new_fn = move |core: &mut ProcessorCore| {
            let res = task(core);
            // ok if send errors here, it just means the join handle was dropped
            let _ = send.send(res);
        };
        let task = Task {
            function: Box::new(new_fn),
        };
        self.tasks.lock().unwrap().push_back(task);
        TaskHandle { recv }
    }
}

impl Default for TaskQueueHandle {
    fn default() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

/// Plugin that allows for an asynchronous thread to add tasks to run during the tick phase on the
/// mutable processor.
///
/// See [TaskQueuePlugin::new()] and [TaskQueueHandle::add_task()].
#[derive(Default)]
pub struct TaskQueuePlugin {
    task_queue: TaskQueueHandle,
}

impl TaskQueuePlugin {
    /// Create the executor and [TaskQueueHandle] to add tasks to the queue.
    pub fn new() -> (Self, TaskQueueHandle) {
        let task_queue = TaskQueueHandle::default();
        let task_queue_rtn = task_queue.clone();
        (Self { task_queue }, task_queue_rtn)
    }
}

impl Plugin for TaskQueuePlugin {
    fn tick(&mut self, proc: &mut ProcessorCore) -> Result<(), UnknownError> {
        trace!("exec task queue");
        let mut tasks = self.task_queue.tasks.lock().unwrap();
        // run each task in queue
        while let Some(task) = tasks.pop_front() {
            (task.function)(proc);
        }
        // drop tasks lock
        trace!("done exec task queue");

        Ok(())
    }

    fn name(&self) -> &str {
        "task queue plugin"
    }
}

impl UninitPlugin for TaskQueuePlugin {
    fn init(
        self: Box<Self>,
        _proc: &mut crate::processor::BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        Ok(self)
    }
}
