#ifndef _DWARF_STRING_H_
#define _DWARF_STRING_H_

#include <unordered_map>

#include "dwarf.h"

/* DWARF tags.  */
static const std::unordered_map<int, const char*> DWARF_TAG_MAP = {
    {DW_TAG_array_type, "DW_TAG_array_type"},

    {DW_TAG_array_type, "DW_TAG_array_type"},
    {DW_TAG_class_type, "DW_TAG_class_type"},
    {DW_TAG_entry_point, "DW_TAG_entry_point"},
    {DW_TAG_enumeration_type, "DW_TAG_enumeration_type"},
    {DW_TAG_formal_parameter, "DW_TAG_formal_parameter"},
    {DW_TAG_imported_declaration, "DW_TAG_imported_declaration"},
    {DW_TAG_label, "DW_TAG_label"},
    {DW_TAG_lexical_block, "DW_TAG_lexical_block"},
    {DW_TAG_member, "DW_TAG_member"},
    {DW_TAG_pointer_type, "DW_TAG_pointer_type"},
    {DW_TAG_reference_type, "DW_TAG_reference_type"},
    {DW_TAG_compile_unit, "DW_TAG_compile_unit"},
    {DW_TAG_string_type, "DW_TAG_string_type"},
    {DW_TAG_structure_type, "DW_TAG_structure_type"},
    {DW_TAG_subroutine_type, "DW_TAG_subroutine_type"},
    {DW_TAG_typedef, "DW_TAG_typedef"},
    {DW_TAG_union_type, "DW_TAG_union_type"},
    {DW_TAG_unspecified_parameters, "DW_TAG_unspecified_parameters"},
    {DW_TAG_variant, "DW_TAG_variant"},
    {DW_TAG_common_block, "DW_TAG_common_block"},
    {DW_TAG_common_inclusion, "DW_TAG_common_inclusion"},
    {DW_TAG_inheritance, "DW_TAG_inheritance"},
    {DW_TAG_inlined_subroutine, "DW_TAG_inlined_subroutine"},
    {DW_TAG_module, "DW_TAG_module"},
    {DW_TAG_ptr_to_member_type, "DW_TAG_ptr_to_member_type"},
    {DW_TAG_set_type, "DW_TAG_set_type"},
    {DW_TAG_subrange_type, "DW_TAG_subrange_type"},
    {DW_TAG_with_stmt, "DW_TAG_with_stmt"},
    {DW_TAG_access_declaration, "DW_TAG_access_declaration"},
    {DW_TAG_base_type, "DW_TAG_base_type"},
    {DW_TAG_catch_block, "DW_TAG_catch_block"},
    {DW_TAG_const_type, "DW_TAG_const_type"},
    {DW_TAG_constant, "DW_TAG_constant"},
    {DW_TAG_enumerator, "DW_TAG_enumerator"},
    {DW_TAG_file_type, "DW_TAG_file_type"},
    {DW_TAG_friend, "DW_TAG_friend"},
    {DW_TAG_namelist, "DW_TAG_namelist"},
    {DW_TAG_namelist_item, "DW_TAG_namelist_item"},
    {DW_TAG_packed_type, "DW_TAG_packed_type"},
    {DW_TAG_subprogram, "DW_TAG_subprogram"},
    {DW_TAG_template_type_parameter, "DW_TAG_template_type_parameter"},
    {DW_TAG_template_value_parameter, "DW_TAG_template_value_parameter"},
    {DW_TAG_thrown_type, "DW_TAG_thrown_type"},
    {DW_TAG_try_block, "DW_TAG_try_block"},
    {DW_TAG_variant_part, "DW_TAG_variant_part"},
    {DW_TAG_variable, "DW_TAG_variable"},
    {DW_TAG_volatile_type, "DW_TAG_volatile_type"},
    {DW_TAG_dwarf_procedure, "DW_TAG_dwarf_procedure"},
    {DW_TAG_restrict_type, "DW_TAG_restrict_type"},
    {DW_TAG_interface_type, "DW_TAG_interface_type"},
    {DW_TAG_namespace, "DW_TAG_namespace"},
    {DW_TAG_imported_module, "DW_TAG_imported_module"},
    {DW_TAG_unspecified_type, "DW_TAG_unspecified_type"},
    {DW_TAG_partial_unit, "DW_TAG_partial_unit"},
    {DW_TAG_imported_unit, "DW_TAG_imported_unit"},
    /* 0x3e reserved.  */
    {DW_TAG_condition, "DW_TAG_condition"},
    {DW_TAG_shared_type, "DW_TAG_shared_type"},
    {DW_TAG_type_unit, "DW_TAG_type_unit"},
    {DW_TAG_rvalue_reference_type, "DW_TAG_rvalue_reference_type"},
    {DW_TAG_template_alias, "DW_TAG_template_alias"},

    /* DWARF 5.  */
    {DW_TAG_atomic_type, "DW_TAG_atomic_type"},

    {DW_TAG_lo_user, "DW_TAG_lo_user"},

    {DW_TAG_MIPS_loop, "DW_TAG_MIPS_loop"},
    {DW_TAG_format_label, "DW_TAG_format_label"},
    {DW_TAG_function_template, "DW_TAG_function_template"},
    {DW_TAG_class_template, "DW_TAG_class_template"},

    {DW_TAG_GNU_BINCL, "DW_TAG_GNU_BINCL"},
    {DW_TAG_GNU_EINCL, "DW_TAG_GNU_EINCL"},

    {DW_TAG_GNU_template_template_param, "DW_TAG_GNU_template_template_param"},
    {DW_TAG_GNU_template_parameter_pack, "DW_TAG_GNU_template_parameter_pack"},
    {DW_TAG_GNU_formal_parameter_pack, "DW_TAG_GNU_formal_parameter_pack"},
    {DW_TAG_GNU_call_site, "DW_TAG_GNU_call_site"},
    {DW_TAG_GNU_call_site_parameter, "DW_TAG_GNU_call_site_parameter"},

    {DW_TAG_hi_user, "DW_TAG_hi_user"},
};

/* DWARF attributes encodings.  */
static const std::unordered_map<int, const char*> DWARF_AT_MAP = {
    {DW_AT_sibling, "DW_AT_sibling"},
    {DW_AT_location, "DW_AT_location"},
    {DW_AT_name, "DW_AT_name"},
    {DW_AT_ordering, "DW_AT_ordering"},
    {DW_AT_subscr_data, "DW_AT_subscr_data"},
    {DW_AT_byte_size, "DW_AT_byte_size"},
    {DW_AT_bit_offset, "DW_AT_bit_offset"},
    {DW_AT_bit_size, "DW_AT_bit_size"},
    {DW_AT_element_list, "DW_AT_element_list"},
    {DW_AT_stmt_list, "DW_AT_stmt_list"},
    {DW_AT_low_pc, "DW_AT_low_pc"},
    {DW_AT_high_pc, "DW_AT_high_pc"},
    {DW_AT_language, "DW_AT_language"},
    {DW_AT_member, "DW_AT_member"},
    {DW_AT_discr, "DW_AT_discr"},
    {DW_AT_discr_value, "DW_AT_discr_value"},
    {DW_AT_visibility, "DW_AT_visibility"},
    {DW_AT_import, "DW_AT_import"},
    {DW_AT_string_length, "DW_AT_string_length"},
    {DW_AT_common_reference, "DW_AT_common_reference"},
    {DW_AT_comp_dir, "DW_AT_comp_dir"},
    {DW_AT_const_value, "DW_AT_const_value"},
    {DW_AT_containing_type, "DW_AT_containing_type"},
    {DW_AT_default_value, "DW_AT_default_value"},
    {DW_AT_inline, "DW_AT_inline"},
    {DW_AT_is_optional, "DW_AT_is_optional"},
    {DW_AT_lower_bound, "DW_AT_lower_bound"},
    {DW_AT_producer, "DW_AT_producer"},
    {DW_AT_prototyped, "DW_AT_prototyped"},
    {DW_AT_return_addr, "DW_AT_return_addr"},
    {DW_AT_start_scope, "DW_AT_start_scope"},
    {DW_AT_bit_stride, "DW_AT_bit_stride"},
    {DW_AT_upper_bound, "DW_AT_upper_bound"},
    {DW_AT_abstract_origin, "DW_AT_abstract_origin"},
    {DW_AT_accessibility, "DW_AT_accessibility"},
    {DW_AT_address_class, "DW_AT_address_class"},
    {DW_AT_artificial, "DW_AT_artificial"},
    {DW_AT_base_types, "DW_AT_base_types"},
    {DW_AT_calling_convention, "DW_AT_calling_convention"},
    {DW_AT_count, "DW_AT_count"},
    {DW_AT_data_member_location, "DW_AT_data_member_location"},
    {DW_AT_decl_column, "DW_AT_decl_column"},
    {DW_AT_decl_file, "DW_AT_decl_file"},
    {DW_AT_decl_line, "DW_AT_decl_line"},
    {DW_AT_declaration, "DW_AT_declaration"},
    {DW_AT_discr_list, "DW_AT_discr_list"},
    {DW_AT_encoding, "DW_AT_encoding"},
    {DW_AT_external, "DW_AT_external"},
    {DW_AT_frame_base, "DW_AT_frame_base"},
    {DW_AT_friend, "DW_AT_friend"},
    {DW_AT_identifier_case, "DW_AT_identifier_case"},
    {DW_AT_macro_info, "DW_AT_macro_info"},
    {DW_AT_namelist_item, "DW_AT_namelist_item"},
    {DW_AT_priority, "DW_AT_priority"},
    {DW_AT_segment, "DW_AT_segment"},
    {DW_AT_specification, "DW_AT_specification"},
    {DW_AT_static_link, "DW_AT_static_link"},
    {DW_AT_type, "DW_AT_type"},
    {DW_AT_use_location, "DW_AT_use_location"},
    {DW_AT_variable_parameter, "DW_AT_variable_parameter"},
    {DW_AT_virtuality, "DW_AT_virtuality"},
    {DW_AT_vtable_elem_location, "DW_AT_vtable_elem_location"},
    {DW_AT_allocated, "DW_AT_allocated"},
    {DW_AT_associated, "DW_AT_associated"},
    {DW_AT_data_location, "DW_AT_data_location"},
    {DW_AT_byte_stride, "DW_AT_byte_stride"},
    {DW_AT_entry_pc, "DW_AT_entry_pc"},
    {DW_AT_use_UTF8, "DW_AT_use_UTF8"},
    {DW_AT_extension, "DW_AT_extension"},
    {DW_AT_ranges, "DW_AT_ranges"},
    {DW_AT_trampoline, "DW_AT_trampoline"},
    {DW_AT_call_column, "DW_AT_call_column"},
    {DW_AT_call_file, "DW_AT_call_file"},
    {DW_AT_call_line, "DW_AT_call_line"},
    {DW_AT_description, "DW_AT_description"},
    {DW_AT_binary_scale, "DW_AT_binary_scale"},
    {DW_AT_decimal_scale, "DW_AT_decimal_scale"},
    {DW_AT_small, "DW_AT_small"},
    {DW_AT_decimal_sign, "DW_AT_decimal_sign"},
    {DW_AT_digit_count, "DW_AT_digit_count"},
    {DW_AT_picture_string, "DW_AT_picture_string"},
    {DW_AT_mutable, "DW_AT_mutable"},
    {DW_AT_threads_scaled, "DW_AT_threads_scaled"},
    {DW_AT_explicit, "DW_AT_explicit"},
    {DW_AT_object_pointer, "DW_AT_object_pointer"},
    {DW_AT_endianity, "DW_AT_endianity"},
    {DW_AT_elemental, "DW_AT_elemental"},
    {DW_AT_pure, "DW_AT_pure"},
    {DW_AT_recursive, "DW_AT_recursive"},
    {DW_AT_signature, "DW_AT_signature"},
    {DW_AT_main_subprogram, "DW_AT_main_subprogram"},
    {DW_AT_data_bit_offset, "DW_AT_data_bit_offset"},
    {DW_AT_const_expr, "DW_AT_const_expr"},
    {DW_AT_enum_class, "DW_AT_enum_class"},
    {DW_AT_linkage_name, "DW_AT_linkage_name"},

    /* DWARF5 attribute values.  */
    {DW_AT_noreturn, "DW_AT_noreturn"},

    {DW_AT_lo_user, "DW_AT_lo_user"},

    {DW_AT_MIPS_fde, "DW_AT_MIPS_fde"},
    {DW_AT_MIPS_loop_begin, "DW_AT_MIPS_loop_begin"},
    {DW_AT_MIPS_tail_loop_begin, "DW_AT_MIPS_tail_loop_begin"},
    {DW_AT_MIPS_epilog_begin, "DW_AT_MIPS_epilog_begin"},
    {DW_AT_MIPS_loop_unroll_factor, "DW_AT_MIPS_loop_unroll_factor"},
    {DW_AT_MIPS_software_pipeline_depth, "DW_AT_MIPS_software_pipeline_depth"},
    {DW_AT_MIPS_linkage_name, "DW_AT_MIPS_linkage_name"},
    {DW_AT_MIPS_stride, "DW_AT_MIPS_stride"},
    {DW_AT_MIPS_abstract_name, "DW_AT_MIPS_abstract_name"},
    {DW_AT_MIPS_clone_origin, "DW_AT_MIPS_clone_origin"},
    {DW_AT_MIPS_has_inlines, "DW_AT_MIPS_has_inlines"},
    {DW_AT_MIPS_stride_byte, "DW_AT_MIPS_stride_byte"},
    {DW_AT_MIPS_stride_elem, "DW_AT_MIPS_stride_elem"},
    {DW_AT_MIPS_ptr_dopetype, "DW_AT_MIPS_ptr_dopetype"},
    {DW_AT_MIPS_allocatable_dopetype, "DW_AT_MIPS_allocatable_dopetype"},
    {DW_AT_MIPS_assumed_shape_dopetype, "DW_AT_MIPS_assumed_shape_dopetype"},
    {DW_AT_MIPS_assumed_size, "DW_AT_MIPS_assumed_size"},

    /* GNU extensions.  */
    {DW_AT_sf_names, "DW_AT_sf_names"},
    {DW_AT_src_info, "DW_AT_src_info"},
    {DW_AT_mac_info, "DW_AT_mac_info"},
    {DW_AT_src_coords, "DW_AT_src_coords"},
    {DW_AT_body_begin, "DW_AT_body_begin"},
    {DW_AT_body_end, "DW_AT_body_end"},
    {DW_AT_GNU_vector, "DW_AT_GNU_vector"},
    {DW_AT_GNU_guarded_by, "DW_AT_GNU_guarded_by"},
    {DW_AT_GNU_pt_guarded_by, "DW_AT_GNU_pt_guarded_by"},
    {DW_AT_GNU_guarded, "DW_AT_GNU_guarded"},
    {DW_AT_GNU_pt_guarded, "DW_AT_GNU_pt_guarded"},
    {DW_AT_GNU_locks_excluded, "DW_AT_GNU_locks_excluded"},
    {DW_AT_GNU_exclusive_locks_required, "DW_AT_GNU_exclusive_locks_required"},
    {DW_AT_GNU_shared_locks_required, "DW_AT_GNU_shared_locks_required"},
    {DW_AT_GNU_odr_signature, "DW_AT_GNU_odr_signature"},
    {DW_AT_GNU_template_name, "DW_AT_GNU_template_name"},
    {DW_AT_GNU_call_site_value, "DW_AT_GNU_call_site_value"},
    {DW_AT_GNU_call_site_data_value, "DW_AT_GNU_call_site_data_value"},
    {DW_AT_GNU_call_site_target, "DW_AT_GNU_call_site_target"},
    {DW_AT_GNU_call_site_target_clobbered, "DW_AT_GNU_call_site_target_clobbered"},
    {DW_AT_GNU_tail_call, "DW_AT_GNU_tail_call"},
    {DW_AT_GNU_all_tail_call_sites, "DW_AT_GNU_all_tail_call_sites"},
    {DW_AT_GNU_all_call_sites, "DW_AT_GNU_all_call_sites"},
    {DW_AT_GNU_all_source_call_sites, "DW_AT_GNU_all_source_call_sites"},
    {DW_AT_GNU_macros, "DW_AT_GNU_macros"},
    {DW_AT_GNU_deleted, "DW_AT_GNU_deleted"},

    {DW_AT_hi_user, "DW_AT_hi_user"},
  };

/* DWARF form encodings.  */
static const std::unordered_map<int, const char*> DWARF_FORM_MAP =
  {
    {DW_FORM_addr, "DW_FORM_addr"},
    {DW_FORM_block2, "DW_FORM_block2"},
    {DW_FORM_block4, "DW_FORM_block4"},
    {DW_FORM_data2, "DW_FORM_data2"},
    {DW_FORM_data4, "DW_FORM_data4"},
    {DW_FORM_data8, "DW_FORM_data8"},
    {DW_FORM_string, "DW_FORM_string"},
    {DW_FORM_block, "DW_FORM_block"},
    {DW_FORM_block1, "DW_FORM_block1"},
    {DW_FORM_data1, "DW_FORM_data1"},
    {DW_FORM_flag, "DW_FORM_flag"},
    {DW_FORM_sdata, "DW_FORM_sdata"},
    {DW_FORM_strp, "DW_FORM_strp"},
    {DW_FORM_udata, "DW_FORM_udata"},
    {DW_FORM_ref_addr, "DW_FORM_ref_addr"},
    {DW_FORM_ref1, "DW_FORM_ref1"},
    {DW_FORM_ref2, "DW_FORM_ref2"},
    {DW_FORM_ref4, "DW_FORM_ref4"},
    {DW_FORM_ref8, "DW_FORM_ref8"},
    {DW_FORM_ref_udata, "DW_FORM_ref_udata"},
    {DW_FORM_indirect, "DW_FORM_indirect"},
    {DW_FORM_sec_offset, "DW_FORM_sec_offset"},
    {DW_FORM_exprloc, "DW_FORM_exprloc"},
    {DW_FORM_flag_present, "DW_FORM_flag_present"},
    {DW_FORM_ref_sig8, "DW_FORM_ref_sig8"},

    {DW_FORM_GNU_ref_alt, "DW_FORM_GNU_ref_alt"}, /* offset in alternate .debuginfo.  */
    {DW_FORM_GNU_strp_alt, "DW_FORM_GNU_strp_alt"}, /* offset in alternate .debug_str. */
  };

/* DWARF language encodings.  */
static const std::unordered_map<int, const char*> DWARF_LANGUAGE_MAP =
  {
    {DW_LANG_C89, "DW_LANG_C89"},	     /* ISO C:1989 */
    {DW_LANG_C, "DW_LANG_C"},		     /* C */
    {DW_LANG_Ada83, "DW_LANG_Ada83"},	     /* ISO Ada:1983 */
    {DW_LANG_C_plus_plus, "DW_LANG_C_plus_plus"},    /* ISO C++:1998 */
    {DW_LANG_Cobol74, "DW_LANG_Cobol74"},	     /* ISO Cobol:1974 */
    {DW_LANG_Cobol85, "DW_LANG_Cobol85"},	     /* ISO Cobol:1985 */
    {DW_LANG_Fortran77, "DW_LANG_Fortran77"},	     /* ISO FORTRAN 77 */
    {DW_LANG_Fortran90, "DW_LANG_Fortran90"},	     /* ISO Fortran 90 */
    {DW_LANG_Pascal83, "DW_LANG_Pascal83"},	     /* ISO Pascal:1983 */
    {DW_LANG_Modula2, "DW_LANG_Modula2"},	     /* ISO Modula-2:1996 */
    {DW_LANG_Java, "DW_LANG_Java"},	     /* Java */
    {DW_LANG_C99, "DW_LANG_C99"},	     /* ISO C:1999 */
    {DW_LANG_Ada95, "DW_LANG_Ada95"},	     /* ISO Ada:1995 */
    {DW_LANG_Fortran95, "DW_LANG_Fortran95"},	     /* ISO Fortran 95 */
    {DW_LANG_PL1, "DW_LANG_PL1"},	     /* ISO PL/1:1976 */
    {DW_LANG_ObjC, "DW_LANG_ObjC"},	     /* Objective-C */
    {DW_LANG_ObjC_plus_plus, "DW_LANG_ObjC_plus_plus"}, /* Objective-C++ */
    {DW_LANG_UPC, "DW_LANG_UPC"},	     /* Unified Parallel C */
    {DW_LANG_D, "DW_LANG_D"},		     /* D */
    {DW_LANG_Python, "DW_LANG_Python"},	     /* Python */
    {DW_LANG_Go, "DW_LANG_Go"},	     /* Go */
    {DW_LANG_Haskell, "DW_LANG_Haskell"},	     /* Haskell */
    {DW_LANG_C_plus_plus_11, "DW_LANG_C_plus_plus_11"}, /* ISO C++:2011 */
    {DW_LANG_C11, "DW_LANG_C11"},	     /* ISO C:2011 */
    {DW_LANG_C_plus_plus_14, "DW_LANG_C_plus_plus_14"}, /* ISO C++:2014 */
    {DW_LANG_Fortran03, "DW_LANG_Fortran03"},	     /* ISO/IEC 1539-1:2004 */
    {DW_LANG_Fortran08, "DW_LANG_Fortran08"},	     /* ISO/IEC 1539-1:2010 */


    {DW_LANG_lo_user, "DW_LANG_lo_user"},
    {DW_LANG_Mips_Assembler, "DW_LANG_Mips_Assembler"}, /* Assembler */
    {DW_LANG_hi_user, "DW_LANG_hi_user"},
  };

/* Information for GNU unwind information.  */
static const std::unordered_map<int, const char*> DWARF_EH_ENCODING_MAP =
  {
    {DW_EH_PE_absptr, "DW_EH_PE_absptr"},
    {DW_EH_PE_omit, "DW_EH_PE_omit"},

    /* FDE data encoding.  */
    {DW_EH_PE_uleb128, "DW_EH_PE_uleb128"},
    {DW_EH_PE_udata2, "DW_EH_PE_udata2"},
    {DW_EH_PE_udata4, "DW_EH_PE_udata4"},
    {DW_EH_PE_udata8, "DW_EH_PE_udata8"},
    {DW_EH_PE_sleb128, "DW_EH_PE_sleb128"},
    {DW_EH_PE_sdata2, "DW_EH_PE_sdata2"},
    {DW_EH_PE_sdata4, "DW_EH_PE_sdata4"},
    {DW_EH_PE_sdata8, "DW_EH_PE_sdata8"},
    {DW_EH_PE_signed, "DW_EH_PE_signed"},

    /* FDE flags.  */
    {DW_EH_PE_pcrel, "DW_EH_PE_pcrel"},
    {DW_EH_PE_textrel, "DW_EH_PE_textrel"},
    {DW_EH_PE_datarel, "DW_EH_PE_datarel"},
    {DW_EH_PE_funcrel, "DW_EH_PE_funcrel"},
    {DW_EH_PE_aligned, "DW_EH_PE_aligned"},

    {DW_EH_PE_indirect, "DW_EH_PE_indirect"},
  };

/* DWARF call frame instruction encodings.  */
static const std::unordered_map<int, const char*> DWARF_CFA_INST_MAP =
  {
    {DW_CFA_advance_loc, "DW_CFA_advance_loc"},
    {DW_CFA_offset, "DW_CFA_offset"},
    {DW_CFA_restore, "DW_CFA_restore"},
    //{DW_CFA_extended, "DW_CFA_extended"},

    {DW_CFA_nop, "DW_CFA_nop"},
    {DW_CFA_set_loc, "DW_CFA_set_loc"},
    {DW_CFA_advance_loc1, "DW_CFA_advance_loc1"},
    {DW_CFA_advance_loc2, "DW_CFA_advance_loc2"},
    {DW_CFA_advance_loc4, "DW_CFA_advance_loc4"},
    {DW_CFA_offset_extended, "DW_CFA_offset_extended"},
    {DW_CFA_restore_extended, "DW_CFA_restore_extended"},
    {DW_CFA_undefined, "DW_CFA_undefined"},
    {DW_CFA_same_value, "DW_CFA_same_value"},
    {DW_CFA_register, "DW_CFA_register"},
    {DW_CFA_remember_state, "DW_CFA_remember_state"},
    {DW_CFA_restore_state, "DW_CFA_restore_state"},
    {DW_CFA_def_cfa, "DW_CFA_def_cfa"},
    {DW_CFA_def_cfa_register, "DW_CFA_def_cfa_register"},
    {DW_CFA_def_cfa_offset, "DW_CFA_def_cfa_offset"},
    {DW_CFA_def_cfa_expression, "DW_CFA_def_cfa_expression"},
    {DW_CFA_expression, "DW_CFA_expression"},
    {DW_CFA_offset_extended_sf, "DW_CFA_offset_extended_sf"},
    {DW_CFA_def_cfa_sf, "DW_CFA_def_cfa_sf"},
    {DW_CFA_def_cfa_offset_sf, "DW_CFA_def_cfa_offset_sf"},
    {DW_CFA_val_offset, "DW_CFA_val_offset"},
    {DW_CFA_val_offset_sf, "DW_CFA_val_offset_sf"},
    {DW_CFA_val_expression, "DW_CFA_val_expression"},

    {DW_CFA_low_user, "DW_CFA_low_user"},
    {DW_CFA_MIPS_advance_loc8, "DW_CFA_MIPS_advance_loc8"},
    {DW_CFA_GNU_window_save, "DW_CFA_GNU_window_save"},
    {DW_CFA_GNU_args_size, "DW_CFA_GNU_args_size"},
    {DW_CFA_GNU_negative_offset_extended, "DW_CFA_GNU_negative_offset_extended"},
    {DW_CFA_high_user, "DW_CFA_high_user"},
  };

/* DWARF location operation encodings.  */
static const std::unordered_map<int, const char*> DWARF_OP_MAP = {
    {DW_OP_addr, "DW_OP_addr"},    /* Constant address.  */
    {DW_OP_deref, "DW_OP_deref"},
    {DW_OP_const1u, "DW_OP_const1u"}, /* Unsigned 1-byte constant.  */
    {DW_OP_const1s, "DW_OP_const1s"}, /* Signed 1-byte constant.  */
    {DW_OP_const2u, "DW_OP_const2u"}, /* Unsigned 2-byte constant.  */
    {DW_OP_const2s, "DW_OP_const2s"}, /* Signed 2-byte constant.  */
    {DW_OP_const4u, "DW_OP_const4u"}, /* Unsigned 4-byte constant.  */
    {DW_OP_const4s, "DW_OP_const4s"}, /* Signed 4-byte constant.  */
    {DW_OP_const8u, "DW_OP_const8u"}, /* Unsigned 8-byte constant.  */
    {DW_OP_const8s, "DW_OP_const8s"}, /* Signed 8-byte constant.  */
    {DW_OP_constu, "DW_OP_constu"},  /* Unsigned LEB128 constant.  */
    {DW_OP_consts, "DW_OP_consts"},  /* Signed LEB128 constant.  */
    {DW_OP_dup, "DW_OP_dup"},
    {DW_OP_drop, "DW_OP_drop"},
    {DW_OP_over, "DW_OP_over"},
    {DW_OP_pick, "DW_OP_pick"},    /* 1-byte stack index.  */
    {DW_OP_swap, "DW_OP_swap"},
    {DW_OP_rot, "DW_OP_rot"},
    {DW_OP_xderef, "DW_OP_xderef"},
    {DW_OP_abs, "DW_OP_abs"},
    {DW_OP_and, "DW_OP_and"},
    {DW_OP_div, "DW_OP_div"},
    {DW_OP_minus, "DW_OP_minus"},
    {DW_OP_mod, "DW_OP_mod"},
    {DW_OP_mul, "DW_OP_mul"},
    {DW_OP_neg, "DW_OP_neg"},
    {DW_OP_not, "DW_OP_not"},
    {DW_OP_or, "DW_OP_or"},
    {DW_OP_plus, "DW_OP_plus"},
    {DW_OP_plus_uconst, "DW_OP_plus_uconst"}, /* Unsigned LEB128 addend.  */
    {DW_OP_shl, "DW_OP_shl"},
    {DW_OP_shr, "DW_OP_shr"},
    {DW_OP_shra, "DW_OP_shra"},
    {DW_OP_xor, "DW_OP_xor"},
    {DW_OP_bra, "DW_OP_bra"},   /* Signed 2-byte constant.  */
    {DW_OP_eq, "DW_OP_eq"},
    {DW_OP_ge, "DW_OP_ge"},
    {DW_OP_gt, "DW_OP_gt"},
    {DW_OP_le, "DW_OP_le"},
    {DW_OP_lt, "DW_OP_lt"},
    {DW_OP_ne, "DW_OP_ne"},
    {DW_OP_skip, "DW_OP_skip"},    /* Signed 2-byte constant.  */
    {DW_OP_lit0, "DW_OP_lit0"},    /* Literal 0.  */
    {DW_OP_lit1, "DW_OP_lit1"},    /* Literal 1.  */
    {DW_OP_lit2, "DW_OP_lit2"},    /* Literal 2.  */
    {DW_OP_lit3, "DW_OP_lit3"},    /* Literal 3.  */
    {DW_OP_lit4, "DW_OP_lit4"},    /* Literal 4.  */
    {DW_OP_lit5, "DW_OP_lit5"},    /* Literal 5.  */
    {DW_OP_lit6, "DW_OP_lit6"},    /* Literal 6.  */
    {DW_OP_lit7, "DW_OP_lit7"},    /* Literal 7.  */
    {DW_OP_lit8, "DW_OP_lit8"},    /* Literal 8.  */
    {DW_OP_lit9, "DW_OP_lit9"},    /* Literal 9.  */
    {DW_OP_lit10, "DW_OP_lit10"},   /* Literal 10.  */
    {DW_OP_lit11, "DW_OP_lit11"},   /* Literal 11.  */
    {DW_OP_lit12, "DW_OP_lit12"},   /* Literal 12.  */
    {DW_OP_lit13, "DW_OP_lit13"},   /* Literal 13.  */
    {DW_OP_lit14, "DW_OP_lit14"},   /* Literal 14.  */
    {DW_OP_lit15, "DW_OP_lit15"},   /* Literal 15.  */
    {DW_OP_lit16, "DW_OP_lit16"},   /* Literal 16.  */
    {DW_OP_lit17, "DW_OP_lit17"},   /* Literal 17.  */
    {DW_OP_lit18, "DW_OP_lit18"},   /* Literal 18.  */
    {DW_OP_lit19, "DW_OP_lit19"},   /* Literal 19.  */
    {DW_OP_lit20, "DW_OP_lit20"},   /* Literal 20.  */
    {DW_OP_lit21, "DW_OP_lit21"},   /* Literal 21.  */
    {DW_OP_lit22, "DW_OP_lit22"},   /* Literal 22.  */
    {DW_OP_lit23, "DW_OP_lit23"},   /* Literal 23.  */
    {DW_OP_lit24, "DW_OP_lit24"},   /* Literal 24.  */
    {DW_OP_lit25, "DW_OP_lit25"},   /* Literal 25.  */
    {DW_OP_lit26, "DW_OP_lit26"},   /* Literal 26.  */
    {DW_OP_lit27, "DW_OP_lit27"},   /* Literal 27.  */
    {DW_OP_lit28, "DW_OP_lit28"},   /* Literal 28.  */
    {DW_OP_lit29, "DW_OP_lit29"},   /* Literal 29.  */
    {DW_OP_lit30, "DW_OP_lit30"},   /* Literal 30.  */
    {DW_OP_lit31, "DW_OP_lit31"},   /* Literal 31.  */
    {DW_OP_reg0, "DW_OP_reg0"},    /* Register 0.  */
    {DW_OP_reg1, "DW_OP_reg1"},    /* Register 1.  */
    {DW_OP_reg2, "DW_OP_reg2"},    /* Register 2.  */
    {DW_OP_reg3, "DW_OP_reg3"},    /* Register 3.  */
    {DW_OP_reg4, "DW_OP_reg4"},    /* Register 4.  */
    {DW_OP_reg5, "DW_OP_reg5"},    /* Register 5.  */
    {DW_OP_reg6, "DW_OP_reg6"},    /* Register 6.  */
    {DW_OP_reg7, "DW_OP_reg7"},    /* Register 7.  */
    {DW_OP_reg8, "DW_OP_reg8"},    /* Register 8.  */
    {DW_OP_reg9, "DW_OP_reg9"},    /* Register 9.  */
    {DW_OP_reg10, "DW_OP_reg10"},   /* Register 10.  */
    {DW_OP_reg11, "DW_OP_reg11"},   /* Register 11.  */
    {DW_OP_reg12, "DW_OP_reg12"},   /* Register 12.  */
    {DW_OP_reg13, "DW_OP_reg13"},   /* Register 13.  */
    {DW_OP_reg14, "DW_OP_reg14"},   /* Register 14.  */
    {DW_OP_reg15, "DW_OP_reg15"},   /* Register 15.  */
    {DW_OP_reg16, "DW_OP_reg16"},   /* Register 16.  */
    {DW_OP_reg17, "DW_OP_reg17"},   /* Register 17.  */
    {DW_OP_reg18, "DW_OP_reg18"},   /* Register 18.  */
    {DW_OP_reg19, "DW_OP_reg19"},   /* Register 19.  */
    {DW_OP_reg20, "DW_OP_reg20"},   /* Register 20.  */
    {DW_OP_reg21, "DW_OP_reg21"},   /* Register 21.  */
    {DW_OP_reg22, "DW_OP_reg22"},   /* Register 22.  */
    {DW_OP_reg23, "DW_OP_reg23"},   /* Register 24.  */
    {DW_OP_reg24, "DW_OP_reg24"},   /* Register 24.  */
    {DW_OP_reg25, "DW_OP_reg25"},   /* Register 25.  */
    {DW_OP_reg26, "DW_OP_reg26"},   /* Register 26.  */
    {DW_OP_reg27, "DW_OP_reg27"},   /* Register 27.  */
    {DW_OP_reg28, "DW_OP_reg28"},   /* Register 28.  */
    {DW_OP_reg29, "DW_OP_reg29"},   /* Register 29.  */
    {DW_OP_reg30, "DW_OP_reg30"},   /* Register 30.  */
    {DW_OP_reg31, "DW_OP_reg31"},   /* Register 31.  */
    {DW_OP_breg0, "DW_OP_breg0"},   /* Base register 0.  */
    {DW_OP_breg1, "DW_OP_breg1"},   /* Base register 1.  */
    {DW_OP_breg2, "DW_OP_breg2"},   /* Base register 2.  */
    {DW_OP_breg3, "DW_OP_breg3"},   /* Base register 3.  */
    {DW_OP_breg4, "DW_OP_breg4"},   /* Base register 4.  */
    {DW_OP_breg5, "DW_OP_breg5"},   /* Base register 5.  */
    {DW_OP_breg6, "DW_OP_breg6"},   /* Base register 6.  */
    {DW_OP_breg7, "DW_OP_breg7"},   /* Base register 7.  */
    {DW_OP_breg8, "DW_OP_breg8"},   /* Base register 8.  */
    {DW_OP_breg9, "DW_OP_breg9"},   /* Base register 9.  */
    {DW_OP_breg10, "DW_OP_breg10"},  /* Base register 10.  */
    {DW_OP_breg11, "DW_OP_breg11"},  /* Base register 11.  */
    {DW_OP_breg12, "DW_OP_breg12"},  /* Base register 12.  */
    {DW_OP_breg13, "DW_OP_breg13"},  /* Base register 13.  */
    {DW_OP_breg14, "DW_OP_breg14"},  /* Base register 14.  */
    {DW_OP_breg15, "DW_OP_breg15"},  /* Base register 15.  */
    {DW_OP_breg16, "DW_OP_breg16"},  /* Base register 16.  */
    {DW_OP_breg17, "DW_OP_breg17"},  /* Base register 17.  */
    {DW_OP_breg18, "DW_OP_breg18"},  /* Base register 18.  */
    {DW_OP_breg19, "DW_OP_breg19"},  /* Base register 19.  */
    {DW_OP_breg20, "DW_OP_breg20"},  /* Base register 20.  */
    {DW_OP_breg21, "DW_OP_breg21"},  /* Base register 21.  */
    {DW_OP_breg22, "DW_OP_breg22"},  /* Base register 22.  */
    {DW_OP_breg23, "DW_OP_breg23"},  /* Base register 23.  */
    {DW_OP_breg24, "DW_OP_breg24"},  /* Base register 24.  */
    {DW_OP_breg25, "DW_OP_breg25"},  /* Base register 25.  */
    {DW_OP_breg26, "DW_OP_breg26"},  /* Base register 26.  */
    {DW_OP_breg27, "DW_OP_breg27"},  /* Base register 27.  */
    {DW_OP_breg28, "DW_OP_breg28"},  /* Base register 28.  */
    {DW_OP_breg29, "DW_OP_breg29"},  /* Base register 29.  */
    {DW_OP_breg30, "DW_OP_breg30"},  /* Base register 30.  */
    {DW_OP_breg31, "DW_OP_breg31"},  /* Base register 31.  */
    {DW_OP_regx, "DW_OP_regx"},    /* Unsigned LEB128 register.  */
    {DW_OP_fbreg, "DW_OP_fbreg"},   /* Signed LEB128 offset.  */
    {DW_OP_bregx, "DW_OP_bregx"},   /* ULEB128 register followed by SLEB128 off. */
    {DW_OP_piece, "DW_OP_piece"},   /* ULEB128 size of piece addressed. */
    {DW_OP_deref_size, "DW_OP_deref_size"},  /* 1-byte size of data retrieved.  */
    {DW_OP_xderef_size, "DW_OP_xderef_size"}, /* 1-byte size of data retrieved.  */
    {DW_OP_nop, "DW_OP_nop"},
    {DW_OP_push_object_address, "DW_OP_push_object_address"},
    {DW_OP_call2, "DW_OP_call2"},
    {DW_OP_call4, "DW_OP_call4"},
    {DW_OP_call_ref, "DW_OP_call_ref"},
    {DW_OP_form_tls_address, "DW_OP_form_tls_address"}, /* TLS offset to address in current thread */
    {DW_OP_call_frame_cfa, "DW_OP_call_frame_cfa"}, /* CFA as determined by CFI.  */
    {DW_OP_bit_piece, "DW_OP_bit_piece"}, /* ULEB128 size and ULEB128 offset in bits.  */
    {DW_OP_implicit_value, "DW_OP_implicit_value"}, /* DW_FORM_block follows opcode.  */
    {DW_OP_stack_value, "DW_OP_stack_value"},  /* No operands, special like DW_OP_piece.  */

    /* GNU extensions.  */
    {DW_OP_GNU_push_tls_address, "DW_OP_GNU_push_tls_address"},
    {DW_OP_GNU_uninit, "DW_OP_GNU_uninit"},
    {DW_OP_GNU_encoded_addr, "DW_OP_GNU_encoded_addr"},
    {DW_OP_GNU_implicit_pointer, "DW_OP_GNU_implicit_pointer"},
    {DW_OP_GNU_entry_value, "DW_OP_GNU_entry_value"},
    {DW_OP_GNU_const_type, "DW_OP_GNU_const_type"},
    {DW_OP_GNU_regval_type, "DW_OP_GNU_regval_type"},
    {DW_OP_GNU_deref_type, "DW_OP_GNU_deref_type"},
    {DW_OP_GNU_convert, "DW_OP_GNU_convert"},
    {DW_OP_GNU_reinterpret, "DW_OP_GNU_reinterpret"},
    {DW_OP_GNU_parameter_ref, "DW_OP_GNU_parameter_ref"},

    {DW_OP_lo_user, "DW_OP_lo_user"}, /* Implementation-defined range start.  */
    {DW_OP_hi_user, "DW_OP_hi_user"},  /* Implementation-defined range end.  */
  };

#endif  // _DWARF_STRING_H_
