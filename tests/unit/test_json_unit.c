/*
 * QSysDB - Comprehensive JSON Validator Unit Tests
 *
 * Tests all aspects of the JSON validator including:
 *   - Valid JSON for all types (objects, arrays, strings, numbers, literals)
 *   - Invalid JSON detection
 *   - Edge cases and boundary conditions
 *   - Unicode handling
 *   - Nested structures
 *   - Whitespace handling
 *   - Error recovery
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qsysdb/types.h>
#include "framework/test_framework.h"

/* External declarations from json.c */
extern int qsysdb_json_validate(const char *json, size_t len);
extern int qsysdb_json_validate_str(const char *json);
extern char qsysdb_json_type(const char *json, size_t len);

static const char *_current_suite_name = "json";

/* ============================================
 * Valid Objects Tests
 * ============================================ */

TEST(empty_object)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{}"));
}

TEST(simple_object)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"key\":\"value\"}"));
}

TEST(object_with_multiple_keys)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"a\":1,\"b\":2,\"c\":3}"));
}

TEST(object_with_nested_object)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"outer\":{\"inner\":\"value\"}}"));
}

TEST(object_with_nested_array)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"items\":[1,2,3]}"));
}

TEST(object_with_all_value_types)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str(
        "{\"str\":\"hello\",\"num\":42,\"float\":3.14,\"bool\":true,\"null\":null,\"arr\":[],\"obj\":{}}"
    ));
}

TEST(deeply_nested_objects)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str(
        "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":\"deep\"}}}}}}"
    ));
}

TEST(object_with_empty_string_key)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"\":\"empty_key\"}"));
}

TEST(object_with_special_chars_in_key)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"key-with-dash\":1}"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"key_with_underscore\":1}"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\"key.with.dot\":1}"));
}

/* ============================================
 * Valid Arrays Tests
 * ============================================ */

TEST(empty_array)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[]"));
}

TEST(array_of_numbers)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[1,2,3,4,5]"));
}

TEST(array_of_strings)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[\"a\",\"b\",\"c\"]"));
}

TEST(array_of_booleans)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[true,false,true]"));
}

TEST(array_of_nulls)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[null,null,null]"));
}

TEST(array_of_mixed_types)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[1,\"two\",true,null,{},[]]"));
}

TEST(nested_arrays)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[[1,2],[3,4],[5,6]]"));
}

TEST(deeply_nested_arrays)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[[[[[[[\"deep\"]]]]]]]"));
}

TEST(array_of_objects)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[{\"a\":1},{\"b\":2},{\"c\":3}]"));
}

TEST(single_element_array)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[42]"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("[\"single\"]"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("[{}]"));
}

/* ============================================
 * Valid Strings Tests
 * ============================================ */

TEST(empty_string)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\""));
}

TEST(simple_string)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"hello world\""));
}

TEST(string_with_spaces)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"   spaces   \""));
}

TEST(string_with_escape_sequences)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"line1\\nline2\""));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"tab\\there\""));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"carriage\\rreturn\""));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"back\\\\slash\""));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"forward\\/slash\""));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"back\\bspace\""));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"form\\ffeed\""));
}

TEST(string_with_escaped_quote)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"say \\\"hello\\\"\""));
}

TEST(string_with_unicode_escape)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\\u0041\""));  /* 'A' */
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\\u00e9\""));  /* e-acute */
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\\u4e2d\""));  /* Chinese character */
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\\uFFFF\""));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\\u0000\""));
}

TEST(string_with_multiple_unicode_escapes)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\\u0048\\u0065\\u006c\\u006c\\u006f\""));
}

TEST(string_with_all_escape_types)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("\"\\\"\\\\\\b\\f\\n\\r\\t\\/\\u0041\""));
}

/* ============================================
 * Valid Numbers Tests
 * ============================================ */

TEST(zero)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("0"));
}

TEST(positive_integers)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("1"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("123"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("9999999999"));
}

TEST(negative_integers)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("-1"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("-123"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("-9999999999"));
}

TEST(negative_zero)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("-0"));
}

TEST(decimal_numbers)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("0.5"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("3.14159"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("-0.5"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("123.456"));
}

TEST(exponential_notation_lowercase)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("1e10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1e+10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1e-10"));
}

TEST(exponential_notation_uppercase)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("1E10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1E+10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1E-10"));
}

TEST(decimal_with_exponent)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("1.5e10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1.5e+10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1.5e-10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1.5E10"));
}

TEST(negative_with_exponent)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("-1e10"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("-1.5e-10"));
}

TEST(large_exponent)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("1e308"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("1e-308"));
}

TEST(very_long_number)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("12345678901234567890"));
}

/* ============================================
 * Valid Literals Tests
 * ============================================ */

TEST(true_literal)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("true"));
}

TEST(false_literal)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("false"));
}

TEST(null_literal)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("null"));
}

/* ============================================
 * Whitespace Handling Tests
 * ============================================ */

TEST(leading_whitespace)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("  {}"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\t{}"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\n{}"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\r\n{}"));
}

TEST(trailing_whitespace)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{}  "));
    TEST_ASSERT_OK(qsysdb_json_validate_str("{}\t"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("{}\n"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("{}\r\n"));
}

TEST(whitespace_around_value)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("  true  "));
    TEST_ASSERT_OK(qsysdb_json_validate_str("\n\n42\n\n"));
}

TEST(whitespace_in_object)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("{ \"a\" : 1 }"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("{\n  \"a\": 1,\n  \"b\": 2\n}"));
}

TEST(whitespace_in_array)
{
    TEST_ASSERT_OK(qsysdb_json_validate_str("[ 1 , 2 , 3 ]"));
    TEST_ASSERT_OK(qsysdb_json_validate_str("[\n  1,\n  2,\n  3\n]"));
}

/* ============================================
 * Invalid Objects Tests
 * ============================================ */

TEST(unclosed_object)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{"));
}

TEST(unopened_object)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("}"));
}

TEST(missing_colon)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{\"key\"}"));
}

TEST(missing_value)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{\"key\":}"));
}

TEST(missing_key)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{:\"value\"}"));
}

TEST(trailing_comma_in_object)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{\"a\":1,}"));
}

TEST(leading_comma_in_object)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{,\"a\":1}"));
}

TEST(double_comma_in_object)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{\"a\":1,,\"b\":2}"));
}

TEST(unquoted_key)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{key:\"value\"}"));
}

TEST(single_quoted_key)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{'key':\"value\"}"));
}

TEST(numeric_key)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{123:\"value\"}"));
}

/* ============================================
 * Invalid Arrays Tests
 * ============================================ */

TEST(unclosed_array)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("["));
}

TEST(unopened_array)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("]"));
}

TEST(trailing_comma_in_array)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("[1,2,3,]"));
}

TEST(leading_comma_in_array)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("[,1,2,3]"));
}

TEST(double_comma_in_array)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("[1,,2]"));
}

TEST(just_comma_in_array)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("[,]"));
}

/* ============================================
 * Invalid Strings Tests
 * ============================================ */

TEST(unclosed_string)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\""));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"unterminated"));
}

TEST(invalid_escape_sequence)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"bad\\x\""));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"bad\\q\""));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"bad\\a\""));
}

TEST(invalid_unicode_escape)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"\\uXXXX\""));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"\\u123\""));  /* Too short */
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"\\u\""));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"\\uGGGG\""));
}

TEST(unescaped_control_character)
{
    char json[] = "\"bad\x01char\"";
    TEST_ASSERT_FAILS(qsysdb_json_validate_str(json));
}

TEST(single_quoted_string)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("'string'"));
}

TEST(newline_in_string)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"line1\nline2\""));
}

/* ============================================
 * Invalid Numbers Tests
 * ============================================ */

TEST(leading_zero)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("01"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("007"));
}

TEST(leading_plus)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("+1"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("+123"));
}

TEST(trailing_decimal_point)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1."));
}

TEST(leading_decimal_point)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str(".5"));
}

TEST(multiple_decimal_points)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1.2.3"));
}

TEST(incomplete_exponent)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1e"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1e+"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1e-"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1E"));
}

TEST(double_exponent)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1e10e5"));
}

TEST(hex_number)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("0x1F"));
}

TEST(octal_number)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("0777"));
}

TEST(nan_value)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("NaN"));
}

TEST(infinity_value)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("Infinity"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("-Infinity"));
}

/* ============================================
 * Invalid Literals Tests
 * ============================================ */

TEST(capitalized_true)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("True"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("TRUE"));
}

TEST(capitalized_false)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("False"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("FALSE"));
}

TEST(capitalized_null)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("Null"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("NULL"));
}

TEST(undefined_literal)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("undefined"));
}

/* ============================================
 * Edge Cases Tests
 * ============================================ */

TEST(empty_input)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str(""));
}

TEST(whitespace_only)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("   "));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\n\t\r"));
}

TEST(null_input)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate(NULL, 0));
}

TEST(garbage_input)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("garbage"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("abc123"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("@#$%"));
}

TEST(trailing_garbage)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("{} garbage"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("[] extra"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("true false"));
}

TEST(multiple_values)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("1 2"));
    TEST_ASSERT_FAILS(qsysdb_json_validate_str("\"a\" \"b\""));
}

/* ============================================
 * JSON Type Detection Tests
 * ============================================ */

TEST(type_object)
{
    TEST_ASSERT_EQ('o', qsysdb_json_type("{}", 2));
    TEST_ASSERT_EQ('o', qsysdb_json_type("{\"a\":1}", 7));
}

TEST(type_array)
{
    TEST_ASSERT_EQ('a', qsysdb_json_type("[]", 2));
    TEST_ASSERT_EQ('a', qsysdb_json_type("[1,2,3]", 7));
}

TEST(type_string)
{
    TEST_ASSERT_EQ('s', qsysdb_json_type("\"\"", 2));
    TEST_ASSERT_EQ('s', qsysdb_json_type("\"hello\"", 7));
}

TEST(type_number)
{
    TEST_ASSERT_EQ('n', qsysdb_json_type("0", 1));
    TEST_ASSERT_EQ('n', qsysdb_json_type("123", 3));
    TEST_ASSERT_EQ('n', qsysdb_json_type("-42", 3));
    TEST_ASSERT_EQ('n', qsysdb_json_type("3.14", 4));
}

TEST(type_true)
{
    TEST_ASSERT_EQ('t', qsysdb_json_type("true", 4));
}

TEST(type_false)
{
    TEST_ASSERT_EQ('f', qsysdb_json_type("false", 5));
}

TEST(type_null)
{
    TEST_ASSERT_EQ('0', qsysdb_json_type("null", 4));
}

TEST(type_with_whitespace)
{
    TEST_ASSERT_EQ('o', qsysdb_json_type("  {}", 4));
    TEST_ASSERT_EQ('a', qsysdb_json_type("\n[]", 3));
    TEST_ASSERT_EQ('t', qsysdb_json_type("\t\ttrue", 6));
}

/* ============================================
 * Complex JSON Tests
 * ============================================ */

TEST(complex_nested_structure)
{
    const char *json =
        "{"
        "  \"name\": \"test\","
        "  \"version\": 1.5,"
        "  \"enabled\": true,"
        "  \"config\": {"
        "    \"timeout\": 30,"
        "    \"retries\": 3,"
        "    \"options\": [\"fast\", \"secure\"]"
        "  },"
        "  \"tags\": [\"a\", \"b\", \"c\"],"
        "  \"data\": null,"
        "  \"nested\": {"
        "    \"level1\": {"
        "      \"level2\": {"
        "        \"level3\": [1, 2, 3]"
        "      }"
        "    }"
        "  }"
        "}";
    TEST_ASSERT_OK(qsysdb_json_validate_str(json));
}

TEST(realistic_api_response)
{
    const char *json =
        "{"
        "\"status\": \"success\","
        "\"code\": 200,"
        "\"data\": {"
        "  \"users\": ["
        "    {\"id\": 1, \"name\": \"Alice\", \"email\": \"alice@example.com\"},"
        "    {\"id\": 2, \"name\": \"Bob\", \"email\": \"bob@example.com\"}"
        "  ],"
        "  \"pagination\": {"
        "    \"page\": 1,"
        "    \"per_page\": 20,"
        "    \"total\": 2,"
        "    \"has_more\": false"
        "  }"
        "},"
        "\"meta\": {"
        "  \"request_id\": \"abc-123\","
        "  \"timestamp\": 1699900000"
        "}"
        "}";
    TEST_ASSERT_OK(qsysdb_json_validate_str(json));
}

TEST(array_of_complex_objects)
{
    const char *json =
        "["
        "  {\"type\": \"event\", \"data\": {\"action\": \"click\", \"target\": \"button\"}},"
        "  {\"type\": \"event\", \"data\": {\"action\": \"hover\", \"target\": \"link\"}},"
        "  {\"type\": \"metric\", \"data\": {\"name\": \"latency\", \"value\": 42.5}}"
        "]";
    TEST_ASSERT_OK(qsysdb_json_validate_str(json));
}

/* ============================================
 * Length-based validation Tests
 * ============================================ */

TEST(validate_with_length)
{
    /* Only validate first 2 characters of "{}" (valid) */
    TEST_ASSERT_OK(qsysdb_json_validate("{} garbage", 2));
}

TEST(validate_partial_json)
{
    /* Partial JSON should fail */
    TEST_ASSERT_FAILS(qsysdb_json_validate("{\"key\":", 7));
}

TEST(validate_zero_length)
{
    TEST_ASSERT_FAILS(qsysdb_json_validate("anything", 0));
}

TEST_MAIN()
