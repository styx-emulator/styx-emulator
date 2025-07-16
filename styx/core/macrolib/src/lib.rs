// SPDX-License-Identifier: BSD-2-Clause
use crate::named_field_ex::{ArgType, NamedFieldEx};
use pbuf::PROST_OPTION_STR;
use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{parse_quote, Attribute, DeriveInput, Path, Token};

pub mod debug;
use debug::PrintDebug;
pub mod named_field_ex;
pub mod pbuf;

pub fn parse_single_path(ts: proc_macro2::TokenStream) -> Path {
    let paths = parse_paths(ts);
    assert_eq!(paths.len(), 1);
    paths[0].clone()
}

/// parse, return a list of syn::Path separated by commas
pub fn parse_paths(ts: proc_macro2::TokenStream) -> Vec<Path> {
    Punctuated::<Path, Token![,]>::parse_terminated
        .parse2(ts)
        .unwrap()
        .into_iter()
        .collect::<Vec<Path>>()
}

/// helper function to get a string repr from a syn::Path, since rust prohibits
/// Display impl in/from this crate
#[inline]
pub fn path_to_string(p: &Path) -> String {
    p.to_token_stream().to_string().replace(' ', "")
}

/// most of the heavy lifting for deriving clap args from google protobuf
/// `message` and `enum` items.
pub fn derive_clap(item: TokenStream) -> TokenStream {
    // clap ref:
    // https://docs.rs/clap/latest/clap/_derive/index.html

    let input = syn::parse2::<DeriveInput>(item).unwrap();
    let data: syn::Data = input.data.clone();
    let attrs = input.attrs;
    let vis = input.vis;
    let ident = input.ident;

    PrintDebug::debugify(&format!("derive_clap: item={ident}"));

    match data {
        // struct / proto message
        syn::Data::Struct(syn::DataStruct {
            struct_token,
            fields,
            semi_token,
        }) => {
            let mut clappable = true;
            let clap_arg_attr: Attribute = parse_quote! { #[arg(long, required(false))] };
            let clap_flatten_attr: Attribute = parse_quote! {#[clap(flatten)]};
            let input_item_name = ident.to_string();

            let field_vec = if let syn::Fields::Named(flds) = &fields {
                flds.named.iter().cloned().collect::<Vec<syn::Field>>()
            } else {
                vec![]
            };

            let mut new_fields: Vec<NamedFieldEx> = Vec::with_capacity(field_vec.len());
            for named_field in field_vec.iter() {
                let type_path = parse_single_path(named_field.ty.to_token_stream());
                let carg = ClapPbHelper::clap_pb_arg_type(&type_path);

                PrintDebug::debugify(&format!(
                    "derive_clap: {}.{} is: {:?} ",
                    input_item_name,
                    named_field.ident.clone().unwrap(),
                    carg
                ));

                match ClapPbHelper::clap_pb_arg_type(&type_path) {
                    ArgType::Arg(arg) => {
                        let mut nfield = named_field.clone();
                        nfield.attrs.push(clap_arg_attr.clone());
                        new_fields.push(NamedFieldEx::new(nfield, ArgType::Arg(arg)))
                    }

                    ArgType::Composite(arg) => {
                        let mut nfield = named_field.clone();
                        nfield.attrs.push(clap_flatten_attr.clone());
                        new_fields.push(NamedFieldEx::new(nfield, ArgType::Composite(arg)))
                    }
                    ArgType::Unsupported(arg) => {
                        clappable = false;
                        new_fields.push(NamedFieldEx::new(
                            named_field.clone(),
                            ArgType::Unsupported(arg),
                        ))
                    }
                    ArgType::Unhandled(arg) => {
                        panic!(
                            "{}",
                            format!("Unhandled arg for clap: {input_item_name} {arg:?}")
                        );
                    }
                }
            }

            if debug::is_dbg() {
                PrintDebug::debugify(&format!("Updated Fields => {input_item_name}"));
                let new_fields_string = new_fields
                    .iter()
                    .map(|nf| format!("\n{}", PrintDebug::field_to_string(&nf.field)))
                    .collect::<Vec<String>>()
                    .join("  ");
                PrintDebug::debugify(&format!("{}\n---", &new_fields_string));
            }

            // the original input, unaltered

            let unaltered_item = quote! {
                #(#attrs)*
                #vis #struct_token #ident
                    #fields
                #semi_token
            };

            // the input with clap derivations
            let clapped_item = {
                let fields = new_fields
                    .iter()
                    .map(|ex| ex.field.clone())
                    .collect::<Vec<syn::Field>>();

                // Getter functions
                let getters = new_fields
                    .iter()
                    .filter_map(|ex| ex.getters())
                    .collect::<Vec<proc_macro2::TokenStream>>();

                let parser_ident = format_ident!("{}Parser", ident.to_string());
                let value_parser_ident = format_ident!("{}ValueParser", ident.to_string());
                quote! {
                        #[derive(clap::Args)]
                        #(#attrs)*
                        #vis #struct_token #ident {
                            #(#fields),*
                        } #semi_token

                        #[derive(clap::Parser, Debug, Clone)]
                        pub struct #parser_ident {
                            #[clap(flatten)]
                            pub inner: #ident,
                        }

                        // support methods for clap parsing

                        impl #ident {
                            /// private function used by [clap::builder::TypedValueParser]
                            fn try_parser_or_default(
                                input_args: Vec<&str>,
                                arg: &clap::Arg,
                            ) -> Result<Self, clap::error::Error> {
                                let mut cp = input_args.to_vec();
                                cp.insert(0, "_cli_");
                                let command = clap::Command::new("prog")
                                    .arg(clap::Arg::new("before_args").num_args(0..))
                                    .arg(arg)
                                    .arg(clap::Arg::new("after_args").num_args(0..).last(true));

                                let matches = command.get_matches_from(cp);
                                let xid = arg.get_id().as_str();
                                if let Some(str_array) = matches.get_many::<String>(xid) {
                                    let mut args = str_array.into_iter().cloned().collect::<Vec<String>>();
                                    let opt_name = format!("--{}", xid.replace("_args", "").replace('_', "-"));
                                    args.insert(0, opt_name);
                                    Ok(#parser_ident::try_parse_from(args)?.inner)
                                } else {
                                    Ok(#ident::default())
                                }
                            }

                            pub fn long_arg_name() -> String {
                                styx_util::camel_to_snake(
                                    std::any::type_name::<#ident>()
                                        .split("::")
                                        .last()
                                        .unwrap(),
                                )
                            }

                            pub fn long_clap_arg_name() -> String {
                                Self::long_arg_name().replace("_", "-")
                            }

                            #(#getters)*
                        }


                        //----------------
                        // A new struct: "ItemValueParser" with an implementation
                        // of clap::builder::TypedValueParser
                        #[derive(Clone, Default)]
                        pub struct #value_parser_ident {}

                        // ValueParser
                        impl clap::builder::TypedValueParser for #value_parser_ident {
                            type Value = #ident;

                            fn parse_ref(
                                &self,
                                _cmd: &clap::Command,
                                _arg: Option<&clap::Arg>,
                                value: &std::ffi::OsStr,
                            ) -> Result<Self::Value, clap::Error> {
                                let input_args = value.to_str().unwrap().to_string();
                                let mut vargs = input_args.split_whitespace().collect::<Vec<&str>>();
                                let arg_name = styx_util::camel_to_snake(stringify!(#ident));
                                let clap_arg_name = styx_util::camel_to_snake(stringify!(#ident)).replace("_", "-");
                                let template_arg =  clap::Arg::new(arg_name)
                                    .required(false)
                                    .long(clap_arg_name.clone())
                                    .action(clap::ArgAction::Set)
                                    .num_args(0..)
                                    .allow_hyphen_values(true)
                                    .value_terminator(";");

                                let vp_arg_name = format!("--{}", clap_arg_name);
                                vargs.insert(0, &vp_arg_name);
                                #ident ::try_parser_or_default(vargs, &template_arg)
                            }
                        }
                }
            };

            if debug::is_dbg() {
                PrintDebug::debugify("vvv New Item Code ");
                PrintDebug::debugify(&clapped_item.to_string());
                PrintDebug::debugify("^^^ --- ");
            }

            if clappable {
                clapped_item
            } else {
                unaltered_item
            }
        }

        // enum / proto enum
        syn::Data::Enum(syn::DataEnum {
            enum_token,
            brace_token: _,
            variants,
        }) => {
            // enum
            quote! {
                #[derive(clap::ValueEnum)]
                #(#attrs)*
                #vis #enum_token #ident {
                    #variants
                }
            }
        }

        _ => panic!("macro expected struct or enum"),
    }
}

/// Helper implementation for deriving clap constructs from tonic-generated
/// protobuf messages and enumerations
pub struct ClapPbHelper {}
impl ClapPbHelper {
    /// determines if the given type used as a rust type for the proto compiler
    pub fn clap_pb_is_rust_type(emitted_type: &str) -> bool {
        match emitted_type {
            // prost types emitted by tonic
            "::prost::alloc::string::String"
            // native rust types (that tonic emits)
            | "f64" | "i64" | "u64" | "f32" | "i32" | "u32" | "u8" | "bool"
            // HashMap is emitted, but not supported by clap
            | "HashMap" => true,
            _ => false,
        }
    }

    /// these types are valid but not supported by clap
    pub fn clap_pb_unsupported_type(emitted_type: &str) -> bool {
        matches!(emitted_type, "HashMap")
    }

    /// determine what sort of arg we have
    pub fn clap_pb_arg_type(p: &syn::Path) -> ArgType {
        if let Some(ty) = ClapPbHelper::clap_pb_get_rust_type(p) {
            let unsupported_rust_type = ClapPbHelper::clap_pb_unsupported_type(&ty);
            let is_proto_rust_type = ClapPbHelper::clap_pb_is_rust_type(&ty);
            let is_composite = !is_proto_rust_type;
            if unsupported_rust_type {
                ArgType::Unsupported(ty)
            } else if is_composite {
                ArgType::Composite(ty)
            } else {
                ArgType::Arg(ty)
            }
        } else {
            ArgType::Unhandled(path_to_string(p))
        }
    }

    /// determine the base rust type
    /// Returning None here implies a parse error,
    ///   ie: the type is not something considered at time of writing this.
    // Dev note: this is a very hacky way to parse this, but syn::Path and
    // segments are way more involved than the subset we are trying to support,
    // which is ONLY those types being emitted by a protobuf compiler
    pub fn clap_pb_get_rust_type(path: &syn::Path) -> Option<String> {
        let p = path_to_string(path);

        if path.segments.len() == 1 || Self::clap_pb_is_rust_type(&p) {
            return Some(p);
        }

        let rust_ty = {
            if p.starts_with(PROST_OPTION_STR) {
                let options_vec = p.split('<').collect::<Vec<&str>>();
                if options_vec.len() == 2 {
                    Some(options_vec[1].split('>').collect::<Vec<&str>>()[0].to_string())
                } else if options_vec.len() == 3 && options_vec[1] == "::prost::alloc::vec::Vec" {
                    Some(options_vec[2].split('>').collect::<Vec<&str>>()[0].to_string())
                } else {
                    None
                }
            } else if p.starts_with("::prost::alloc::vec::Vec<") {
                let options_vec = p.split('<').collect::<Vec<&str>>();
                if options_vec.len() == 2 {
                    Some(options_vec[1].split('>').collect::<Vec<&str>>()[0].to_string())
                } else {
                    None
                }
            } else if p.starts_with("::std::collections::HashMap<") {
                Some("HashMap".to_string())
            } else {
                None
            }
        };
        rust_ty
    }

    /// these are all NamedFields
    pub fn fq_option_to_just_option(fields: syn::Fields) -> Vec<syn::Field> {
        fields
            .iter()
            .map(|in_field| {
                let in_field = in_field.clone();
                let syn_path = parse_single_path(in_field.ty.to_token_stream());
                let tpath = path_to_string(&syn_path);
                PrintDebug::debugify(&format!("tpath: {tpath}"));
                if tpath.starts_with(PROST_OPTION_STR) {
                    let field_name = in_field.ident;
                    let attrs = in_field.attrs;
                    let vis = in_field.vis;
                    let base_type_ident = format_ident!(
                        "{}",
                        Self::clap_pb_get_rust_type(&syn_path).unwrap_or_else(|| {
                            panic!("Can't determine field type");
                        })
                    );

                    let nfts = quote! {
                        #(#attrs)*
                        #vis #field_name : Option<#base_type_ident>
                    };
                    match syn::Field::parse_named.parse2(nfts.clone()) {
                        Ok(new_field) => {
                            PrintDebug::debugify(&format!(
                                "\nWriting new field:\n    =>{:?}\n---",
                                nfts.to_string()
                            ));
                            new_field
                        }
                        _ => {
                            panic!("Could not re-write the field");
                        }
                    }
                } else {
                    in_field
                }
            })
            .collect()
    }

    /// clap can handle `Option<T>` but seems to have issues when fully
    /// qualified, such as `core::option::Option<T>`. Tonic, perhaps
    /// rightly so, generated `::core::option::Option<T>`. This
    /// code re-writes the fully qualified type to just `Option<T>`
    /// # panics
    /// - if it sees a Union
    pub fn fix_tonic_clap(item: syn::DeriveInput) -> TokenStream {
        let data = item.data.clone();
        let attrs = item.attrs.clone();
        let vis = item.vis;
        let ident = item.ident;
        PrintDebug::debugify_separator();
        match data {
            syn::Data::Struct(syn::DataStruct {
                struct_token,
                fields,
                semi_token,
            }) => {
                let new_fields = Self::fq_option_to_just_option(fields);
                quote! {
                    #(#attrs)*
                    #vis #struct_token #ident {
                        #(#new_fields),*
                    }
                    #semi_token
                }
            }

            // enums OK
            syn::Data::Enum(syn::DataEnum {
                enum_token,
                brace_token: _,
                variants,
            }) => quote! {
                    #(#attrs)*
                    #vis #enum_token #ident {
                        #variants
                    }
            },

            // no unions
            syn::Data::Union(syn::DataUnion {
                union_token: _,
                fields: _,
            }) => {
                panic!("Didn't expect a Union")
            }
        }
    }
}

/// macro used to derive clap args support for emulation args
pub fn derive_styx_app_args(item: TokenStream) -> TokenStream {
    // clap ref:
    // https://docs.rs/clap/latest/clap/_derive/index.html

    let input = syn::parse2::<DeriveInput>(item).unwrap();
    let data = input.data.clone();
    let attrs = input.attrs;
    let vis = input.vis;
    let ident = input.ident;

    PrintDebug::debugify(&format!("derive_clap: item={ident}"));

    match data {
        // struct / proto message
        syn::Data::Struct(syn::DataStruct {
            struct_token,
            fields,
            semi_token,
        }) => {
            let new_field_vec = if let syn::Fields::Named(flds) = &fields {
                flds.named.iter().cloned().collect::<Vec<syn::Field>>()
            } else {
                vec![]
            };

            let reference_item = quote! {
                #(#attrs)*
                #vis #struct_token #ident {
                    /// Persistence ID
                    #[arg(long, default_value="0", required=false, hide=true)]
                    id: i32,

                    /// Target
                    #[arg(long)]
                    target: ::styx_core::grpc::args::Target,
                    /// full path to firmware to emulate
                    #[arg(long, required(true))]
                    pub firmware_path: String,
                    /// Use -1 for default ipc port, 0 for random, or a port number
                    #[arg(long, required(false), allow_hyphen_values(true), default_value_t=-1)]
                    pub ipc_port: i32,
                    #[arg(long, allow_hyphen_values(true), value_parser=::styx_core::grpc::args::TracePluginArgsValueParser{})]
                    pub trace_plugin_args: Option<::styx_core::grpc::args::TracePluginArgs>,
                    #[arg(long, allow_hyphen_values(true), value_parser=::styx_core::grpc::args::EmuRunLimitsValueParser{})]
                    pub emu_run_limits: Option<::styx_core::grpc::args::EmuRunLimits>,
                    #[arg(long, allow_hyphen_values(true), value_parser=::styx_core::grpc::args::RawLoaderArgsValueParser{})]
                    pub raw_loader_args: Option<::styx_core::grpc::args::RawLoaderArgs>,
                } #semi_token
            };

            let ref_item_tokens: TokenStream = reference_item;

            let ref_input = syn::parse2::<DeriveInput>(ref_item_tokens).unwrap();

            let ref_fields = match ref_input.data {
                syn::Data::Struct(syn::DataStruct {
                    struct_token: _,
                    fields,
                    semi_token: _,
                }) => {
                    if let syn::Fields::Named(flds) = &fields {
                        flds.named.iter().cloned().collect::<Vec<syn::Field>>()
                    } else {
                        vec![]
                    }
                }
                _ => vec![],
            };

            let mut params_for_new: Vec<proc_macro2::TokenStream> = vec![];
            let mut assign_for_new: Vec<proc_macro2::TokenStream> = vec![];

            let mut all_fields = vec![];
            for field in ref_fields.iter() {
                all_fields.push(field.clone());
            }
            for field in new_field_vec.iter() {
                all_fields.push(field.clone());
            }

            for f in all_fields.iter() {
                let ident = f.ident.clone().unwrap();
                let ty = f.ty.clone();
                params_for_new.push(quote!(#ident: #ty));
                assign_for_new.push(quote!(#ident));
            }
            let mut assign_for_has_emulation_args: Vec<proc_macro2::TokenStream> = vec![];
            let mut from_item_to_emulation_args: Vec<proc_macro2::TokenStream> = vec![];
            let mut emulation_args_to_item: Vec<proc_macro2::TokenStream> = vec![];
            for f in ref_fields.iter() {
                let ident = f.ident.clone().unwrap();
                assign_for_has_emulation_args.push(quote!(#ident: self. #ident.clone().into()));
                from_item_to_emulation_args.push(quote!(#ident: value. #ident.into()));
                let name = format!("{ident}");
                if name == "target" {
                    emulation_args_to_item.push(quote!(#ident: value. target().into()));
                } else {
                    emulation_args_to_item.push(quote!(#ident: value. #ident .clone()));
                }
            }
            emulation_args_to_item.push(quote!(..Default::default()));
            quote! {

                #[derive(clap::Parser, Debug, Default, ::serde::Serialize, ::serde::Deserialize)]
                #[derive(styx_macros_args::HasTarget)]
                #[derive(styx_macros_args::HasEmuRunLimits)]
                #[derive(styx_macros_args::HasEmulationOptArgs)]
                #[derive(styx_macros_args::HasRawLoaderArgs)]
                #[derive(styx_macros_args::HasTracePluginArgs)]
                #[derive(Clone)]

                #(#attrs)*
                #vis #struct_token #ident {
                    #(#all_fields),*
                } #semi_token

                impl #ident  {
                    pub fn yaml(&self) -> String {
                        serde_yaml::to_string(self).unwrap()
                    }

                    #[allow(clippy::too_many_arguments)]
                    pub fn new(
                        #(#params_for_new),*
                    ) -> Self {
                        Self {
                            #(#assign_for_new),*
                        }
                    }
                }

                impl ::styx_core::grpc::args::HasEmulationArgs for #ident {
                    fn as_emulation_args(&self) -> ::styx_core::grpc::args::EmulationArgs {
                        ::styx_core::grpc::args::EmulationArgs {
                            #(#assign_for_has_emulation_args),*
                        }
                    }
                }

                // EmulationArgs to ITEM
                impl From<#ident> for ::styx_core::grpc::args::EmulationArgs {
                    fn from(value: #ident) -> Self {
                        Self {
                            #(#from_item_to_emulation_args),*
                        }
                    }
                }

                // ITEM to EmulationArgs
                impl From<::styx_core::grpc::args::EmulationArgs> for #ident {
                    #[allow(clippy::needless_update)]
                    fn from(value: ::styx_core::grpc::args::EmulationArgs) -> Self {
                        Self {
                            #(#emulation_args_to_item),*
                        }
                    }
                }

                impl ::styx_core::grpc::ToArgVec for #ident {
                    fn arg_vec(&self) -> Vec<String> {
                        let target_name = clap::ValueEnum::to_possible_value(&self.target)
                            .unwrap()
                            .get_name()
                            .to_string();
                        let mut vargs: Vec<String> = vec![
                            "--target".into(),
                            target_name.into(),
                            "--firmware-path".into(),
                            self.firmware_path.clone(),
                            "--ipc-port".into(), self.ipc_port.to_string(),
                        ];
                        if let Some(ref tpa) = self.trace_plugin_args {
                            let arg_string = ::styx_core::grpc::ToArgVec::arg_string(tpa);
                            vargs.extend(vec!["--trace-plugin-args".into(), arg_string])
                        }
                        if let Some(ref rla) = self.raw_loader_args {
                            let arg_string = ::styx_core::grpc::ToArgVec::arg_string(rla);
                            vargs.extend(vec!["--raw-loader-args".into(), arg_string])
                        }
                        if let Some(ref emu_run_limits) = self.emu_run_limits {
                            let arg_string = ::styx_core::grpc::ToArgVec::arg_string(emu_run_limits);
                            vargs.extend(vec!["--emu-run-limits".into(), arg_string])
                        }

                        vargs
                    }
                }
            }
        }

        _ => panic!("macro expected struct"),
    }
}
