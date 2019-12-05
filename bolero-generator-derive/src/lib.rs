extern crate proc_macro;

mod generator_attr;

use generator_attr::GeneratorAttr;
use proc_macro::TokenStream;
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    export::{Span, TokenStream2},
    parse_macro_input, Attribute, Data, DataEnum, DataStruct, DataUnion, DeriveInput, Error,
    Fields, FieldsNamed, FieldsUnnamed, Generics, Ident, Visibility, WhereClause,
};

// TODO
// #[proc_macro_derive(ValueGenerator, attributes(generator))]
// pub fn derive_value_generator(input: TokenStream) -> TokenStream {
//     let input = parse_macro_input!(input as DeriveInput);
//     let name = input.ident.clone();
//     let generator = input.ident;

//     let expanded = quote! {
//         impl bolero_generator::TypeGeneratorWithParams for #name {
//             type Output = #generator;

//             fn gen_with() -> Self::Output {
//                 Default::default()
//             }
//         }

//         impl ValueGenerator for #generator {
//             type Output = #name;

//             fn generate<D: bolero_generator::driver::Driver>(&self, rng: &mut R) -> Option<Self> {
//                 None
//             }
//         }
//     };

//     TokenStream::from(expanded)
// }

#[proc_macro_derive(TypeGenerator, attributes(generator))]
pub fn derive_type_generator(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match input.data {
        Data::Struct(data) => {
            generate_struct_type_gen(input.attrs, input.vis, input.ident, input.generics, data)
        }
        Data::Enum(data) => {
            generate_enum_type_gen(input.attrs, input.vis, input.ident, input.generics, data)
        }
        Data::Union(data) => {
            generate_union_type_gen(input.attrs, input.vis, input.ident, input.generics, data)
        }
    }
    .into()
}

fn generate_struct_type_gen(
    _attrs: Vec<Attribute>,
    _vis: Visibility,
    name: Ident,
    mut generics: Generics,
    data_struct: DataStruct,
) -> TokenStream2 {
    let where_clause = generics.make_where_clause();
    let value = generate_fields_type_gen(&name, &data_struct.fields, where_clause);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote!(
        impl #impl_generics TypeGenerator for #name #ty_generics #where_clause {
            fn generate<D: bolero_generator::driver::Driver>(__driver: &mut D) -> Option<Self> {
                Some(#value)
            }
        }
    )
}

fn generate_enum_type_gen(
    _attrs: Vec<Attribute>,
    _vis: Visibility,
    name: Ident,
    mut generics: Generics,
    data_enum: DataEnum,
) -> TokenStream2 {
    let where_clause = generics.make_where_clause();
    let variant_max = data_enum.variants.len();
    let variant_upper = lower_type_index(variant_max, variant_max, name.span());

    let variants: Vec<_> = data_enum
        .variants
        .iter()
        .enumerate()
        .map(|(idx, variant)| {
            let variant_name = &variant.ident;
            let constructor = quote!(#name::#variant_name);
            let value = generate_fields_type_gen(constructor, &variant.fields, where_clause);

            let idx = lower_type_index(idx, variant_max, variant_name.span());
            quote!(#idx => Some(#value),)
        })
        .collect();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote!(
        impl #impl_generics TypeGenerator for #name #ty_generics #where_clause {
            fn generate<D: bolero_generator::driver::Driver>(__driver: &mut D) -> Option<Self> {
                match bolero_generator::ValueGenerator::generate(&(0..#variant_upper), __driver)? {
                    #(#variants)*
                    _ => unreachable!("Value outside of range"),
                }
            }
        }
    )
}

fn generate_union_type_gen(
    _attrs: Vec<Attribute>,
    _vis: Visibility,
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
            let value = GeneratorAttr::from_attrs(field.attrs.iter());
            value.apply_constraint(&field.ty, where_clause);

            let idx = lower_type_index(
                idx,
                field_max,
                field_name.as_ref().map(|n| n.span()).unwrap_or(span),
            );
            quote!(#idx => Some(#name { #field_name: #value }),)
        })
        .collect();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote!(
        impl #impl_generics TypeGenerator for #name #ty_generics #where_clause {
            fn generate<D: bolero_generator::driver::Driver>(__driver: &mut D) -> Option<Self> {
                match bolero_generator::ValueGenerator::generate(&(0..#field_upper), __driver)? {
                    #(#fields)*
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

fn generate_fields_unnamed_type_gen<C: ToTokens>(
    constructor: C,
    fields: &FieldsUnnamed,
    where_clause: &mut WhereClause,
) -> TokenStream2 {
    let fields = fields.unnamed.iter().map(|field| {
        let value = GeneratorAttr::from_attrs(field.attrs.iter());
        value.apply_constraint(&field.ty, where_clause);
        value
    });
    quote!(#constructor ( #(#fields,)* ))
}

fn generate_fields_named_type_gen<C: ToTokens>(
    constructor: C,
    fields: &FieldsNamed,
    where_clause: &mut WhereClause,
) -> TokenStream2 {
    let fields = fields.named.iter().map(|field| {
        let name = &field.ident;
        let value = GeneratorAttr::from_attrs(field.attrs.iter());
        value.apply_constraint(&field.ty, where_clause);
        quote!(#name: #value,)
    });
    quote!(#constructor { #(#fields)* })
}
