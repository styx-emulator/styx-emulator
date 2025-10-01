// Post-generation script for Styx component templates

let crate_name = variable::get("crate_name");
let component_type = variable::get("component_type");

print(`
Generated ${component_type}: ${crate_name}

Next steps:
1. Review and customize the generated code in src/lib.rs
2. Add your component to the appropriate Cargo.toml workspace
3. Implement the required trait methods for your ${component_type}
4. Run 'cargo build' to verify the component compiles
5. Add tests in tests/ directory

For more information, see the documentation in the generated README.md
`);
