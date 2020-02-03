extern crate proc_macro;

mod generator_attr;

use generator_attr::GeneratorAttr;
use proc_macro::TokenStream;
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    export::{Span, TokenStream2},
    parse_macro_input,
    spanned::Spanned,
    Attribute, Data, DataEnum, DataStruct, DataUnion, DeriveInput, Error, Fields, FieldsNamed,
    FieldsUnnamed, Generics, Ident, WhereClause,
};

/// Derive the an implementation of `TypeGenerator` for the given type.
///
/// The `#[generator(my_custom_generator())]` attribute can be used
/// to customize how fields are generated. If no generator is specified,
/// the `TypeGenerator` implementation will be used.
#[proc_macro_derive(TypeGenerator, attributes(generator))]
pub fn derive_type_generator(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match input.data {
        Data::Struct(data) => {
            generate_struct_type_gen(input.attrs, input.ident, input.generics, data)
        }
        Data::Enum(data) => generate_enum_type_gen(input.attrs, input.ident, input.generics, data),
        Data::Union(data) => {
            generate_union_type_gen(input.attrs, input.ident, input.generics, data)
        }
    }
    .into()
}

fn generate_struct_type_gen(
    _attrs: Vec<Attribute>,
    name: Ident,
    mut generics: Generics,
    data_struct: DataStruct,
) -> TokenStream2 {
    let where_clause = generics.make_where_clause();
    let value = generate_fields_type_gen(&name, &data_struct.fields, where_clause);
    let destructure = generate_fields_type_destructure(&name, &data_struct.fields);
    let mutate = generate_fields_type_mutate(&data_struct.fields);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote!(
        impl #impl_generics TypeGenerator for #name #ty_generics #where_clause {
            fn generate<__BOLERO_DRIVER: bolero_generator::driver::Driver>(__bolero_driver: &mut __BOLERO_DRIVER) -> Option<Self> {
                Some(#value)
            }

            fn mutate<__BOLERO_DRIVER: bolero_generator::driver::Driver>(&mut self, __bolero_driver: &mut __BOLERO_DRIVER) -> Option<()> {
                let #destructure = self;
                #mutate
                Some(())
            }
        }
    )
}

fn generate_enum_type_gen(
    _attrs: Vec<Attribute>,
    name: Ident,
    mut generics: Generics,
    data_enum: DataEnum,
) -> TokenStream2 {
    let where_clause = generics.make_where_clause();
    let variant_max = data_enum.variants.len();
    let variant_upper = lower_type_index(variant_max, variant_max, name.span());

    let gen_variants: Vec<_> = data_enum
        .variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let variant_name = &variant.ident;
            let span = variant_name.span();
            let constructor = quote_spanned!(span=> #name::#variant_name);
            let value = generate_fields_type_gen(constructor, &variant.fields, where_clause);

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
            let mutate = generate_fields_type_mutate(&variant.fields);

            quote_spanned!(span=> #destructure => {
                #mutate
                Some(())
            })
        })
        .collect();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote!(
        impl #impl_generics TypeGenerator for #name #ty_generics #where_clause {
            fn generate<__BOLERO_DRIVER: bolero_generator::driver::Driver>(__bolero_driver: &mut __BOLERO_DRIVER) -> Option<Self> {
                let __bolero_selection = bolero_generator::ValueGenerator::generate(&(0..#variant_upper), __bolero_driver)?;
                Some(match __bolero_selection {
                    #(#gen_variants)*
                    _ => unreachable!("Value outside of range"),
                })
            }

            fn mutate<__BOLERO_DRIVER: bolero_generator::driver::Driver>(&mut self, __bolero_driver: &mut __BOLERO_DRIVER) -> Option<()> {
                let __bolero_prev_selection = match self {
                    #(#gen_lookup)*
                };

                let __bolero_new_selection = bolero_generator::ValueGenerator::generate(&(0..#variant_upper), __bolero_driver)?;

                if __bolero_prev_selection == __bolero_new_selection {
                    match self {
                        #(#gen_mutate)*
                    }
                } else {
                    *self = match __bolero_new_selection {
                        #(#gen_variants)*
                        _ => unreachable!("Value outside of range"),
                    };
                    Some(())
                }
            }
        }
    )
}

fn generate_union_type_gen(
    _attrs: Vec<Attribute>,
    name: Ident,
    mut generics: Generics,
    data_union: DataUnion,
) -> TokenStream2 {
    let span = name.span();
    let where_clause = generics.make_where_clause();
    let field_max = data_union.fields.named.len();
    let field_upper = lower_type_index(field_max, field_max, name.span());

    let fields: Vec<_> = data_union
        .fields
        .named
        .iter()
        .enumerate()
        .map(|(idx, field)| {
            let field_name = &field.ident;
            let generator = GeneratorAttr::from_attrs(field.attrs.iter());
            generator.apply_constraint(&field.ty, where_clause);

            let idx = lower_type_index(
                idx,
                field_max,
                field_name.as_ref().map(|n| n.span()).unwrap_or(span),
            );
            let span = generator.span();
            let value = generator.value_generate();
            quote_spanned!(span=>
                #idx => Some(#name { #field_name: #value })
            )
        })
        .collect();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote!(
        impl #impl_generics TypeGenerator for #name #ty_generics #where_clause {
            fn generate<__BOLERO_DRIVER: bolero_generator::driver::Driver>(__bolero_driver: &mut __BOLERO_DRIVER) -> Option<Self> {
                match bolero_generator::ValueGenerator::generate(&(0..#field_upper), __bolero_driver)? {
                    #(#fields,)*
                    _ => unreachable!("Value outside of range"),
                }
            }
        }
    )
}

fn lower_type_index(value: usize, max: usize, span: Span) -> TokenStream2 {
    assert!(value <= max);

    if max == 0 {
        return Error::new(span, "Empty enums cannot be generated").to_compile_error();
    }

    if max < core::u8::MAX as usize {
        let value = value as u8;
        return quote_spanned!(span=> #value);
    }

    if max < core::u16::MAX as usize {
        let value = value as u16;
        return quote_spanned!(span=> #value);
    }

    assert!(max < core::u32::MAX as usize);
    let value = value as u32;
    return quote_spanned!(span=> #value);
}

fn generate_fields_type_gen<C: ToTokens>(
    constructor: C,
    fields: &Fields,
    where_clause: &mut WhereClause,
) -> TokenStream2 {
    match fields {
        Fields::Named(fields) => generate_fields_named_type_gen(constructor, fields, where_clause),
        Fields::Unnamed(fields) => {
            generate_fields_unnamed_type_gen(constructor, fields, where_clause)
        }
        Fields::Unit => quote!(#constructor),
    }
}

fn generate_fields_type_mutate(fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(fields) => generate_fields_named_type_mutate(fields),
        Fields::Unnamed(fields) => generate_fields_unnamed_type_mutate(fields),
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
    constructor: C,
    fields: &FieldsUnnamed,
    where_clause: &mut WhereClause,
) -> TokenStream2 {
    let fields = fields.unnamed.iter().map(|field| {
        let generator = GeneratorAttr::from_attrs(field.attrs.iter());
        generator.apply_constraint(&field.ty, where_clause);
        let value = generator.value_generate();
        quote!(#value)
    });
    quote!(#constructor ( #(#fields,)* ))
}

fn generate_fields_unnamed_type_mutate(fields: &FieldsUnnamed) -> TokenStream2 {
    let fields = fields.unnamed.iter().enumerate().map(|(index, field)| {
        let value = Ident::new(&format!("__bolero_unnamed_{}", index), field.span());
        let generator = GeneratorAttr::from_attrs(field.attrs.iter());

        let span = generator.span();
        quote_spanned!(span=>
            bolero_generator::ValueGenerator::mutate(&(#generator), __bolero_driver, #value)?
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
    constructor: C,
    fields: &FieldsNamed,
    where_clause: &mut WhereClause,
) -> TokenStream2 {
    let fields = fields.named.iter().map(|field| {
        let name = &field.ident;
        let generator = GeneratorAttr::from_attrs(field.attrs.iter());
        generator.apply_constraint(&field.ty, where_clause);
        let value = generator.value_generate();
        let span = generator.span();
        quote_spanned!(span=>
            #name: #value
        )
    });
    quote!(#constructor { #(#fields,)* })
}

fn generate_fields_named_type_mutate(fields: &FieldsNamed) -> TokenStream2 {
    let fields = fields.named.iter().map(|field| {
        let name = &field.ident;
        let generator = GeneratorAttr::from_attrs(field.attrs.iter());

        let span = generator.span();
        quote_spanned!(span=>
            bolero_generator::ValueGenerator::mutate(&(#generator), __bolero_driver, #name)?
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
