extern crate proc_macro;

mod generator_attr;

use generator_attr::GeneratorAttr;
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    parse_macro_input, parse_quote, spanned::Spanned, Data, DataEnum, DataStruct, DataUnion,
    DeriveInput, Error, Fields, FieldsNamed, FieldsUnnamed, GenericParam, Generics, Ident,
};

fn crate_ident(from: FoundCrate) -> Ident {
    let krate = match from {
        FoundCrate::Itself => String::from("crate"),
        FoundCrate::Name(n) => n,
    };
    Ident::new(&krate, Span::call_site())
}

fn crate_path() -> TokenStream2 {
    // prefer referring to the generator crate, if present
    if let Ok(krate) = crate_name("bolero-generator") {
        let krate = crate_ident(krate);
        return quote!(#krate);
    }
    if let Ok(krate) = crate_name("bolero") {
        let krate = crate_ident(krate);
        return quote!(#krate::generator::bolero_generator);
    }
    panic!("current crate seems to import neither bolero nor bolero-generator, but does use the TypeGenerator derive macro")
}

/// Derive the an implementation of `TypeGenerator` for the given type.
///
/// The `#[generator(my_custom_generator())]` attribute can be used
/// to customize how fields are generated. If no generator is specified,
/// the `TypeGenerator` implementation will be used.
#[proc_macro_derive(TypeGenerator, attributes(generator))]
pub fn derive_type_generator(input: TokenStream) -> TokenStream {
    let krate = crate_path();
    let derive_input = parse_macro_input!(input as DeriveInput);
    let name = derive_input.ident;

    // Add `T: TypeGenerator` bounds to each generic type `T`
    let generics = add_trait_bound(derive_input.generics, &krate);

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // The `generate` and `mutate` methods depend on the data type
    let (generate_method, mutate_method) = match derive_input.data {
        Data::Struct(data) => generate_struct_type_gen(&krate, &name, data),
        Data::Enum(data) => generate_enum_type_gen(&krate, &name, data),
        Data::Union(data) => generate_union_type_gen(&krate, &name, data),
    };

    // Generate the implementation for the type
    quote!(
        #[automatically_derived]
        impl #impl_generics #krate::TypeGenerator for #name #ty_generics #where_clause {
            #generate_method

            #mutate_method
        }
    )
    .into()
}

/// Add a bound `T: TypeGenerator` to each type parameter `T`
fn add_trait_bound(mut generics: Generics, krate: &TokenStream2) -> Generics {
    generics.params.iter_mut().for_each(|param| {
        if let GenericParam::Type(type_param) = param {
            type_param.bounds.push(parse_quote!(#krate::TypeGenerator));
        }
    });
    generics
}

/// Create the `generate` and `mutate` methods for the derived `TypeGenerator` impl of a struct
fn generate_struct_type_gen(
    krate: &TokenStream2,
    name: &Ident,
    data_struct: DataStruct,
) -> (TokenStream2, TokenStream2) {
    let value = generate_fields_type_gen(krate, name, &data_struct.fields);
    let destructure = generate_fields_type_destructure(name, &data_struct.fields);
    let mutate_body = generate_fields_type_mutate(krate, &data_struct.fields);
    let driver_cache = generate_fields_type_driver_cache(krate, &data_struct.fields);

    let generate_method = quote!(
        #[inline]
        fn generate<__BOLERO_DRIVER: #krate::driver::Driver>(__bolero_driver: &mut __BOLERO_DRIVER) -> Option<Self> {
            __bolero_driver.enter_product::<Self, _, _>(
                |__bolero_driver| Some(#value)
            )
        }
    );
    let mutate_method = quote!(
        #[inline]
        fn mutate<__BOLERO_DRIVER: #krate::driver::Driver>(&mut self, __bolero_driver: &mut __BOLERO_DRIVER) -> Option<()> {
            __bolero_driver.enter_product::<Self, _, _>(
                |__bolero_driver| {
                    let #destructure = self;
                    #mutate_body
                    Some(())
                }
            )
        }

        #[inline]
        fn driver_cache<__BOLERO_DRIVER: #krate::driver::Driver>(self, __bolero_driver: &mut __BOLERO_DRIVER) {
            let #destructure = self;
            #driver_cache
        }
    );
    (generate_method, mutate_method)
}

/// Create the `generate` and `mutate` methods for the derived `TypeGenerator` impl of an enum
fn generate_enum_type_gen(
    krate: &TokenStream2,
    name: &Ident,
    data_enum: DataEnum,
) -> (TokenStream2, TokenStream2) {
    let variant_max = data_enum.variants.len();
    let base_case: usize = 0;

    let variant_names: Vec<_> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let span = variant.span();
            let name = variant.ident.to_string();
            quote_spanned!(span=> #name,)
        })
        .collect();
    let variant_names = quote_spanned!(name.span()=> &[#(#variant_names)*]);

    let gen_variants: Vec<_> = data_enum
        .variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let variant_name = &variant.ident;
            let span = variant_name.span();
            let constructor = quote_spanned!(span=> #name::#variant_name);
            let value = generate_fields_type_gen(krate, constructor, &variant.fields);

            let idx = lower_type_index(idx, variant_max, span);
            quote_spanned!(span=> #idx => #value,)
        })
        .collect();

    let gen_lookup: Vec<_> = data_enum
        .variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let variant_name = &variant.ident;
            let span = variant_name.span();
            let constructor = quote_spanned!(span=> #name::#variant_name);
            let wildcard = generate_fields_type_wildcard(constructor, &variant.fields);
            let idx = lower_type_index(idx, variant_max, span);
            quote_spanned!(span=> #wildcard => #idx,)
        })
        .collect();

    let gen_mutate: Vec<_> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;
            let span = variant_name.span();
            let constructor = quote_spanned!(span=> #name::#variant_name);
            let destructure = generate_fields_type_destructure(constructor, &variant.fields);
            let mutate = generate_fields_type_mutate(krate, &variant.fields);

            quote_spanned!(span=> #destructure => {
                #mutate
                Some(())
            })
        })
        .collect();

    let gen_driver_cache: Vec<_> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;
            let span = variant_name.span();
            let constructor = quote_spanned!(span=> #name::#variant_name);
            let destructure = generate_fields_type_destructure(constructor, &variant.fields);
            let driver_cache = generate_fields_type_driver_cache(krate, &variant.fields);

            quote_spanned!(span=> #destructure => {
                #driver_cache
            })
        })
        .collect();

    let generate_method = quote!(
        #[inline]
        fn generate<__BOLERO_DRIVER: #krate::driver::Driver>(__bolero_driver: &mut __BOLERO_DRIVER) -> Option<Self> {
            __bolero_driver.enter_sum::<Self, _, _>(
                Some(#variant_names),
                #variant_max,
                #base_case,
                |__bolero_driver, __bolero_selection| {
                    Some(match __bolero_selection {
                        #(#gen_variants)*
                        _ => unreachable!("Value outside of range"),
                    })
                }
            )
        }
    );

    let mutate_method = quote!(
        #[inline]
        fn mutate<__BOLERO_DRIVER: #krate::driver::Driver>(&mut self, __bolero_driver: &mut __BOLERO_DRIVER) -> Option<()> {
            __bolero_driver.enter_sum::<Self, _, _>(
                Some(#variant_names),
                #variant_max,
                #base_case,
                |__bolero_driver, __bolero_new_selection| {
                    let __bolero_prev_selection = match self {
                        #(#gen_lookup)*
                    };

                    if __bolero_prev_selection == __bolero_new_selection {
                        match self {
                            #(#gen_mutate)*
                        }
                    } else {
                        let next = match __bolero_new_selection {
                            #(#gen_variants)*
                            _ => unreachable!("Value outside of range"),
                        };
                        match ::core::mem::replace(self, next) {
                            #(#gen_driver_cache)*
                        }
                        Some(())
                    }
                }
            )
        }

        #[inline]
        fn driver_cache<__BOLERO_DRIVER: #krate::driver::Driver>(self, __bolero_driver: &mut __BOLERO_DRIVER) {
            match self {
                #(#gen_driver_cache)*
            }
        }
    );
    (generate_method, mutate_method)
}

/// Create the `generate` and `mutate` methods for the derived `TypeGenerator` impl of a union
fn generate_union_type_gen(
    krate: &TokenStream2,
    name: &Ident,
    data_union: DataUnion,
) -> (TokenStream2, TokenStream2) {
    let span = name.span();
    let field_max = data_union.fields.named.len();
    let field_upper = lower_type_index(field_max, field_max, name.span());

    let base_case: usize = 0;

    let variant_names: Vec<_> = data_union
        .fields
        .named
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let span = variant.span();
            let name = if let Some(name) = variant.ident.as_ref() {
                name.to_string()
            } else {
                format!("<UnnamedUnionVariant{idx}>")
            };
            quote_spanned!(span=> #name,)
        })
        .collect();
    let variant_names = quote_spanned!(name.span()=> &[#(#variant_names)*]);

    let fields: Vec<_> = data_union
        .fields
        .named
        .iter()
        .enumerate()
        .map(|(idx, field)| {
            let field_name = &field.ident;
            let generator = GeneratorAttr::from_attrs(krate, field.attrs.iter());

            let idx = lower_type_index(
                idx,
                field_max,
                field_name.as_ref().map(|n| n.span()).unwrap_or(span),
            );
            let span = generator.span();
            let value = generator.value_generate();
            quote_spanned!(span=>
                #idx => Some(#name { #field_name: #value }),
            )
        })
        .collect();

    let generate_method = quote!(
        #[inline]
        fn generate<__BOLERO_DRIVER: #krate::driver::Driver>(__bolero_driver: &mut __BOLERO_DRIVER) -> Option<Self> {
            __bolero_driver.enter_sum::<Self, _, _>(
                Some(#variant_names),
                #field_upper,
                #base_case,
                |__bolero_driver, __bolero_selection| {
                    match __bolero_selection {
                        #(#fields)*
                        _ => unreachable!("Value outside of range"),
                    }
                }
            )
        }
    );

    // The `mutate` method doesn't apply to unions
    let mutate_method = quote!();

    (generate_method, mutate_method)
}

fn lower_type_index(value: usize, max: usize, span: Span) -> TokenStream2 {
    assert!(value <= max);

    if max == 0 {
        return Error::new(span, "Empty enums cannot be generated").to_compile_error();
    }

    quote_spanned!(span=> #value)
}

fn generate_fields_type_gen<C: ToTokens>(
    krate: &TokenStream2,
    constructor: C,
    fields: &Fields,
) -> TokenStream2 {
    match fields {
        Fields::Named(fields) => generate_fields_named_type_gen(krate, constructor, fields),
        Fields::Unnamed(fields) => generate_fields_unnamed_type_gen(krate, constructor, fields),
        Fields::Unit => quote!(#constructor),
    }
}

fn generate_fields_type_mutate(krate: &TokenStream2, fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(fields) => generate_fields_named_type_mutate(krate, fields),
        Fields::Unnamed(fields) => generate_fields_unnamed_type_mutate(krate, fields),
        Fields::Unit => quote!(),
    }
}

fn generate_fields_type_driver_cache(krate: &TokenStream2, fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(fields) => generate_fields_named_type_driver_cache(krate, fields),
        Fields::Unnamed(fields) => generate_fields_unnamed_type_driver_cache(krate, fields),
        Fields::Unit => quote!(),
    }
}

fn generate_fields_type_wildcard<C: ToTokens>(constructor: C, fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(_) => quote!(#constructor { .. }),
        Fields::Unnamed(fields) => generate_fields_unnamed_type_wildcard(constructor, fields),
        Fields::Unit => quote!(#constructor),
    }
}

fn generate_fields_type_destructure<C: ToTokens>(constructor: C, fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(fields) => generate_fields_named_type_destructure(constructor, fields),
        Fields::Unnamed(fields) => generate_fields_unnamed_type_destructure(constructor, fields),
        Fields::Unit => quote!(#constructor),
    }
}

fn generate_fields_unnamed_type_gen<C: ToTokens>(
    krate: &TokenStream2,
    constructor: C,
    fields: &FieldsUnnamed,
) -> TokenStream2 {
    let fields = fields.unnamed.iter().map(|field| {
        let generator = GeneratorAttr::from_attrs(krate, field.attrs.iter());
        let value = generator.value_generate();
        quote!(#value)
    });
    quote!(#constructor ( #(#fields,)* ))
}

fn generate_fields_unnamed_type_mutate(
    krate: &TokenStream2,
    fields: &FieldsUnnamed,
) -> TokenStream2 {
    let fields = fields.unnamed.iter().enumerate().map(|(index, field)| {
        let value = Ident::new(&format!("__bolero_unnamed_{}", index), field.span());
        let generator = GeneratorAttr::from_attrs(krate, field.attrs.iter());

        let span = generator.span();
        quote_spanned!(span=>
            #krate::ValueGenerator::mutate(&(#generator), __bolero_driver, #value)?
        )
    });
    quote!(#(#fields;)*)
}

fn generate_fields_unnamed_type_driver_cache(
    krate: &TokenStream2,
    fields: &FieldsUnnamed,
) -> TokenStream2 {
    let fields = fields.unnamed.iter().enumerate().map(|(index, field)| {
        let value = Ident::new(&format!("__bolero_unnamed_{}", index), field.span());
        let generator = GeneratorAttr::from_attrs(krate, field.attrs.iter());

        let span = generator.span();
        quote_spanned!(span=>
            #krate::ValueGenerator::driver_cache(&(#generator), __bolero_driver, #value)
        )
    });
    quote!(#(#fields;)*)
}

fn generate_fields_unnamed_type_wildcard<C: ToTokens>(
    constructor: C,
    fields: &FieldsUnnamed,
) -> TokenStream2 {
    let fields = fields.unnamed.iter().map(|_| quote!(_));
    quote!(#constructor (#(#fields),*))
}

fn generate_fields_unnamed_type_destructure<C: ToTokens>(
    constructor: C,
    fields: &FieldsUnnamed,
) -> TokenStream2 {
    let fields = fields
        .unnamed
        .iter()
        .enumerate()
        .map(|(index, field)| Ident::new(&format!("__bolero_unnamed_{}", index), field.span()));
    quote!(#constructor (#(#fields),*))
}

fn generate_fields_named_type_gen<C: ToTokens>(
    krate: &TokenStream2,
    constructor: C,
    fields: &FieldsNamed,
) -> TokenStream2 {
    let fields = fields.named.iter().map(|field| {
        let name = &field.ident;
        let generator = GeneratorAttr::from_attrs(krate, field.attrs.iter());
        let value = generator.value_generate();
        let span = generator.span();
        quote_spanned!(span=>
            #name: #value
        )
    });
    quote!(#constructor { #(#fields,)* })
}

fn generate_fields_named_type_mutate(krate: &TokenStream2, fields: &FieldsNamed) -> TokenStream2 {
    let fields = fields.named.iter().map(|field| {
        let name = &field.ident;
        let generator = GeneratorAttr::from_attrs(krate, field.attrs.iter());

        let span = generator.span();
        quote_spanned!(span=>
            #krate::ValueGenerator::mutate(&(#generator), __bolero_driver, #name)?
        )
    });
    quote!(#(#fields;)*)
}

fn generate_fields_named_type_driver_cache(
    krate: &TokenStream2,
    fields: &FieldsNamed,
) -> TokenStream2 {
    let fields = fields.named.iter().map(|field| {
        let name = &field.ident;
        let generator = GeneratorAttr::from_attrs(krate, field.attrs.iter());

        let span = generator.span();
        quote_spanned!(span=>
            #krate::ValueGenerator::driver_cache(&(#generator), __bolero_driver, #name)
        )
    });
    quote!(#(#fields;)*)
}

fn generate_fields_named_type_destructure<C: ToTokens>(
    constructor: C,
    fields: &FieldsNamed,
) -> TokenStream2 {
    let fields = fields.named.iter().map(|field| &field.ident);
    quote!(#constructor { #(#fields,)* })
}
