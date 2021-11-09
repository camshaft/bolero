use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::quote_spanned;
use syn::{
    parse_macro_input, spanned::Spanned as _, token::Colon, AttributeArgs, ItemFn, Visibility,
};

#[proc_macro_attribute]
pub fn test(config: TokenStream, body: TokenStream) -> TokenStream {
    let config = parse_macro_input!(config as AttributeArgs);
    let body = parse_macro_input!(body as ItemFn);

    compile(config, body).into()
}

fn compile(_config: AttributeArgs, mut body: ItemFn) -> TokenStream2 {
    // TODO config

    let inner = Ident::new("inner", body.sig.ident.span());
    let vis = core::mem::replace(&mut body.vis, Visibility::Inherited);
    let name = core::mem::replace(&mut body.sig.ident, inner.clone());
    let test_name = name.to_string();
    let span = body.span();
    let mut attrs = core::mem::take(&mut body.attrs);

    if test_name != "main" {
        attrs.push(syn::parse_quote!(#[cfg_attr(not(rmc), test)]));
    }

    let mut args = vec![];
    let mut fields = vec![];

    for (idx, input) in body.sig.inputs.iter_mut().enumerate() {
        match input {
            syn::FnArg::Typed(arg) => {
                let span = arg.span();
                fields.push(syn::Field {
                    attrs: core::mem::take(&mut arg.attrs),
                    vis: Visibility::Inherited,
                    ident: None,
                    colon_token: Some(Colon(span)),
                    ty: *arg.ty.clone(),
                });
            }
            _ => continue,
        }

        args.push(Ident::new(&format!("input_{}", idx), span));
    }

    if args.is_empty() {
        todo!("register test in linker");
    }

    quote_spanned! {span=>
        #(#attrs)*
        // when compiling with rmc, export the full path
        #[cfg_attr(rmc, export_name = concat!(module_path!(), "::", #test_name))]
        #vis fn #name() {
            #[allow(unused_imports)]
            use bolero::{TargetLocation, generator::*};

            #body

            #[allow(non_upper_snake_case)]
            const __BOLERO__ITEM_PATH: &str = concat!(module_path!(), "::", #test_name);
            const __BOLERO__ITEM_PATH_REG_LEN: usize = __BOLERO__ITEM_PATH.len() + 4;

            #[cfg(not(rmc))]
            #[used]
            #[cfg_attr(
                any(target_os = "linux", target_os = "android"),
                link_section = ".note.bolero"
            )]
            #[cfg_attr(target_os = "freebsd", link_section = ".note.bolero")]
            #[cfg_attr(
                any(target_os = "macos", target_os = "ios"),
                link_section = "__DATA,__bolero"
            )]
            #[cfg_attr(windows, link_section = ".debug_bolero")]
            static __BOLERO__ITEM_PATH_REG: [u8; __BOLERO__ITEM_PATH_REG_LEN] = {
                let mut bytes = [0u8; __BOLERO__ITEM_PATH_REG_LEN];
                let len_bytes = (__BOLERO__ITEM_PATH.len() as u32).to_be_bytes();
                bytes[0] = len_bytes[0];
                bytes[1] = len_bytes[1];
                bytes[2] = len_bytes[2];
                bytes[3] = len_bytes[3];

                let mut idx = 4;
                while idx < __BOLERO__ITEM_PATH.len() {
                    bytes[idx] = __BOLERO__ITEM_PATH.as_bytes()[idx - 4];
                    idx += 1;
                }

                bytes
            };

            let location = TargetLocation {
                package_name: env!("CARGO_PKG_NAME"),
                manifest_dir: env!("CARGO_MANIFEST_DIR"),
                module_path: module_path!(),
                file: file!(),
                line: line!(),
                item_path: __BOLERO__ITEM_PATH,
                test_name: Some(String::from(#test_name)),
            };

            // TODO enable config
            bolero::test(location).with_type().for_each(|(#(#args,)*)| {
                #inner(#(#args,)*)
            });
        }
    }
}
