/*
 * QSysDB - Unit tests for JSON validator
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <qsysdb/types.h>

/* External declarations */
extern int qsysdb_json_validate(const char *json, size_t len);
extern int qsysdb_json_validate_str(const char *json);
extern char qsysdb_json_type(const char *json, size_t len);

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    test_##name(); \
    printf("OK\n"); \
} while(0)

#define ASSERT_OK(expr) do { \
    int _ret = (expr); \
    if (_ret != QSYSDB_OK) { \
        printf("FAIL: %s returned %d\n", #expr, _ret); \
        exit(1); \
    } \
} while(0)

#define ASSERT_ERR(expr) do { \
    int _ret = (expr); \
    if (_ret == QSYSDB_OK) { \
        printf("FAIL: %s should have failed\n", #expr); \
        exit(1); \
    } \
} while(0)

TEST(valid_objects)
{
    ASSERT_OK(qsysdb_json_validate_str("{}"));
    ASSERT_OK(qsysdb_json_validate_str("{\"key\":\"value\"}"));
    ASSERT_OK(qsysdb_json_validate_str("{\"a\":1,\"b\":2}"));
    ASSERT_OK(qsysdb_json_validate_str("{\"nested\":{\"inner\":true}}"));
    ASSERT_OK(qsysdb_json_validate_str("{\"key\":null}"));
}

TEST(valid_arrays)
{
    ASSERT_OK(qsysdb_json_validate_str("[]"));
    ASSERT_OK(qsysdb_json_validate_str("[1,2,3]"));
    ASSERT_OK(qsysdb_json_validate_str("[\"a\",\"b\",\"c\"]"));
    ASSERT_OK(qsysdb_json_validate_str("[[1,2],[3,4]]"));
    ASSERT_OK(qsysdb_json_validate_str("[{\"a\":1},{\"b\":2}]"));
}

TEST(valid_strings)
{
    ASSERT_OK(qsysdb_json_validate_str("\"\""));
    ASSERT_OK(qsysdb_json_validate_str("\"hello\""));
    ASSERT_OK(qsysdb_json_validate_str("\"hello world\""));
    ASSERT_OK(qsysdb_json_validate_str("\"escape\\ntest\""));
    ASSERT_OK(qsysdb_json_validate_str("\"unicode\\u0041test\""));
    ASSERT_OK(qsysdb_json_validate_str("\"quote\\\"test\""));
}

TEST(valid_numbers)
{
    ASSERT_OK(qsysdb_json_validate_str("0"));
    ASSERT_OK(qsysdb_json_validate_str("123"));
    ASSERT_OK(qsysdb_json_validate_str("-456"));
    ASSERT_OK(qsysdb_json_validate_str("3.14159"));
    ASSERT_OK(qsysdb_json_validate_str("-0.5"));
    ASSERT_OK(qsysdb_json_validate_str("1e10"));
    ASSERT_OK(qsysdb_json_validate_str("1.5e-3"));
    ASSERT_OK(qsysdb_json_validate_str("1E+5"));
}

TEST(valid_literals)
{
    ASSERT_OK(qsysdb_json_validate_str("true"));
    ASSERT_OK(qsysdb_json_validate_str("false"));
    ASSERT_OK(qsysdb_json_validate_str("null"));
}

TEST(valid_whitespace)
{
    ASSERT_OK(qsysdb_json_validate_str("  {}  "));
    ASSERT_OK(qsysdb_json_validate_str("\n{\n}\n"));
    ASSERT_OK(qsysdb_json_validate_str("\t{\t}\t"));
    ASSERT_OK(qsysdb_json_validate_str("{ \"a\" : 1 }"));
    ASSERT_OK(qsysdb_json_validate_str("[\n  1,\n  2\n]"));
}

TEST(invalid_objects)
{
    ASSERT_ERR(qsysdb_json_validate_str("{"));
    ASSERT_ERR(qsysdb_json_validate_str("}"));
    ASSERT_ERR(qsysdb_json_validate_str("{\"key\"}"));
    ASSERT_ERR(qsysdb_json_validate_str("{\"key\":}"));
    ASSERT_ERR(qsysdb_json_validate_str("{:\"value\"}"));
    ASSERT_ERR(qsysdb_json_validate_str("{\"a\":1,}"));
    ASSERT_ERR(qsysdb_json_validate_str("{,\"a\":1}"));
}

TEST(invalid_arrays)
{
    ASSERT_ERR(qsysdb_json_validate_str("["));
    ASSERT_ERR(qsysdb_json_validate_str("]"));
    ASSERT_ERR(qsysdb_json_validate_str("[,]"));
    ASSERT_ERR(qsysdb_json_validate_str("[1,]"));
    ASSERT_ERR(qsysdb_json_validate_str("[,1]"));
}

TEST(invalid_strings)
{
    ASSERT_ERR(qsysdb_json_validate_str("\""));
    ASSERT_ERR(qsysdb_json_validate_str("\"unterminated"));
    ASSERT_ERR(qsysdb_json_validate_str("\"bad\\escape\""));
    ASSERT_ERR(qsysdb_json_validate_str("\"bad\\uXXXX\""));
    ASSERT_ERR(qsysdb_json_validate_str("\"bad\\u123\""));
}

TEST(invalid_numbers)
{
    ASSERT_ERR(qsysdb_json_validate_str("01"));
    ASSERT_ERR(qsysdb_json_validate_str("+1"));
    ASSERT_ERR(qsysdb_json_validate_str(".5"));
    ASSERT_ERR(qsysdb_json_validate_str("1."));
    ASSERT_ERR(qsysdb_json_validate_str("1e"));
    ASSERT_ERR(qsysdb_json_validate_str("1e+"));
}

TEST(invalid_misc)
{
    ASSERT_ERR(qsysdb_json_validate_str(""));
    ASSERT_ERR(qsysdb_json_validate_str("garbage"));
    ASSERT_ERR(qsysdb_json_validate_str("True"));
    ASSERT_ERR(qsysdb_json_validate_str("FALSE"));
    ASSERT_ERR(qsysdb_json_validate_str("NULL"));
    ASSERT_ERR(qsysdb_json_validate_str("{} garbage"));
}

TEST(json_type)
{
    assert(qsysdb_json_type("{}", 2) == 'o');
    assert(qsysdb_json_type("[]", 2) == 'a');
    assert(qsysdb_json_type("\"\"", 2) == 's');
    assert(qsysdb_json_type("123", 3) == 'n');
    assert(qsysdb_json_type("-42", 3) == 'n');
    assert(qsysdb_json_type("true", 4) == 't');
    assert(qsysdb_json_type("false", 5) == 'f');
    assert(qsysdb_json_type("null", 4) == '0');
    assert(qsysdb_json_type("  {}", 4) == 'o');  /* With whitespace */
}

TEST(complex_json)
{
    const char *complex =
        "{"
        "  \"name\": \"test\","
        "  \"version\": 1.5,"
        "  \"enabled\": true,"
        "  \"config\": {"
        "    \"timeout\": 30,"
        "    \"retries\": 3"
        "  },"
        "  \"tags\": [\"a\", \"b\", \"c\"],"
        "  \"data\": null"
        "}";

    ASSERT_OK(qsysdb_json_validate_str(complex));
}

int main(void)
{
    printf("Running JSON validator tests...\n");

    RUN_TEST(valid_objects);
    RUN_TEST(valid_arrays);
    RUN_TEST(valid_strings);
    RUN_TEST(valid_numbers);
    RUN_TEST(valid_literals);
    RUN_TEST(valid_whitespace);
    RUN_TEST(invalid_objects);
    RUN_TEST(invalid_arrays);
    RUN_TEST(invalid_strings);
    RUN_TEST(invalid_numbers);
    RUN_TEST(invalid_misc);
    RUN_TEST(json_type);
    RUN_TEST(complex_json);

    printf("\nAll JSON tests passed!\n");
    return 0;
}
