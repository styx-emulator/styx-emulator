// Pre-generation script for Styx component templates

let component_type = variable::get("component_type");
let component_name = variable::get("component_name");

// Set crate name based on component type and name
let crate_name = switch component_type {
    "processor" => `styx-${component_name}-processor`,
    "event-controller" => `styx-${component_name}`,
    "peripheral" => `styx-${component_name}`,
    "plugin" => `styx-${component_name}`,
    _ => component_name,
};

variable::set("crate_name", crate_name);
variable::set("project-name", crate_name);

// Convert component name to PascalCase for struct names
fn to_pascal_case(s) {
    let parts = s.split('-');
    let result = "";
    for part in parts {
        if part.len() > 0 {
            let first = part.sub_string(0, 1).to_upper();
            let rest = part.sub_string(1, part.len());
            result += first + rest;
        }
    }
    result
}

let struct_name = to_pascal_case(component_name);
variable::set("struct_name", struct_name);
variable::set("struct_name_builder", struct_name + "Builder");
variable::set("struct_name_controller", struct_name + "Controller");
