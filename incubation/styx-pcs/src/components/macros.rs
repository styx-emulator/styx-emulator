// SPDX-License-Identifier: BSD-2-Clause

/// Construct a new [`super::Component`] from an `id` and `item`.
///
/// The `item` determines the Component's `T`.
///
/// ```
/// use styx_pcs::component;
///
/// struct MyCoolComponent;
/// let component = component!("my_cool_component", MyCoolComponent);
/// ```
///
/// The macro is needed to grab source location information.
#[macro_export]
macro_rules! component {
    ($id:expr, $item:expr) => {
        $crate::components::Component {
            id: $id,
            item: $item,
            file: file!(),
            line: line!(),
            module_path: module_path!(),
        }
    };
}
