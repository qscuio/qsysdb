/*
 * QSysDB - Hierarchical State Database with Kernel Support
 * json.c - Lightweight JSON validator
 *
 * This is a validation-only JSON parser. It checks if the input is valid JSON
 * but does not build a parse tree. Values are stored and retrieved as strings.
 *
 * Copyright (c) 2024
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <qsysdb/types.h>

/* Parser state */
struct json_parser {
    const char *input;
    const char *end;
    const char *pos;
    int depth;
    int max_depth;
};

/* Forward declarations */
static int parse_value(struct json_parser *p);
static int parse_object(struct json_parser *p);
static int parse_array(struct json_parser *p);
static int parse_string(struct json_parser *p);
static int parse_number(struct json_parser *p);
static int parse_literal(struct json_parser *p, const char *lit, size_t len);

/*
 * Skip whitespace
 */
static void skip_whitespace(struct json_parser *p)
{
    while (p->pos < p->end) {
        char c = *p->pos;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p->pos++;
        } else {
            break;
        }
    }
}

/*
 * Parse a JSON string
 */
static int parse_string(struct json_parser *p)
{
    if (p->pos >= p->end || *p->pos != '"') {
        return QSYSDB_ERR_BADJSON;
    }
    p->pos++;  /* Skip opening quote */

    while (p->pos < p->end) {
        char c = *p->pos++;

        if (c == '"') {
            return QSYSDB_OK;  /* End of string */
        }

        if (c == '\\') {
            /* Escape sequence */
            if (p->pos >= p->end) {
                return QSYSDB_ERR_BADJSON;
            }
            c = *p->pos++;
            switch (c) {
            case '"':
            case '\\':
            case '/':
            case 'b':
            case 'f':
            case 'n':
            case 'r':
            case 't':
                break;
            case 'u':
                /* Unicode escape: \uXXXX */
                if (p->pos + 4 > p->end) {
                    return QSYSDB_ERR_BADJSON;
                }
                for (int i = 0; i < 4; i++) {
                    c = *p->pos++;
                    if (!isxdigit((unsigned char)c)) {
                        return QSYSDB_ERR_BADJSON;
                    }
                }
                break;
            default:
                return QSYSDB_ERR_BADJSON;
            }
        } else if ((unsigned char)c < 0x20) {
            /* Control characters not allowed in strings */
            return QSYSDB_ERR_BADJSON;
        }
    }

    return QSYSDB_ERR_BADJSON;  /* Unterminated string */
}

/*
 * Parse a JSON number
 */
static int parse_number(struct json_parser *p)
{
    const char *start = p->pos;

    /* Optional minus */
    if (p->pos < p->end && *p->pos == '-') {
        p->pos++;
    }

    /* Integer part */
    if (p->pos >= p->end) {
        return QSYSDB_ERR_BADJSON;
    }

    if (*p->pos == '0') {
        p->pos++;
    } else if (*p->pos >= '1' && *p->pos <= '9') {
        p->pos++;
        while (p->pos < p->end && isdigit((unsigned char)*p->pos)) {
            p->pos++;
        }
    } else {
        return QSYSDB_ERR_BADJSON;
    }

    /* Fractional part */
    if (p->pos < p->end && *p->pos == '.') {
        p->pos++;
        if (p->pos >= p->end || !isdigit((unsigned char)*p->pos)) {
            return QSYSDB_ERR_BADJSON;
        }
        while (p->pos < p->end && isdigit((unsigned char)*p->pos)) {
            p->pos++;
        }
    }

    /* Exponent part */
    if (p->pos < p->end && (*p->pos == 'e' || *p->pos == 'E')) {
        p->pos++;
        if (p->pos < p->end && (*p->pos == '+' || *p->pos == '-')) {
            p->pos++;
        }
        if (p->pos >= p->end || !isdigit((unsigned char)*p->pos)) {
            return QSYSDB_ERR_BADJSON;
        }
        while (p->pos < p->end && isdigit((unsigned char)*p->pos)) {
            p->pos++;
        }
    }

    /* Must have consumed at least one character */
    if (p->pos == start) {
        return QSYSDB_ERR_BADJSON;
    }

    return QSYSDB_OK;
}

/*
 * Parse a literal (true, false, null)
 */
static int parse_literal(struct json_parser *p, const char *lit, size_t len)
{
    if ((size_t)(p->end - p->pos) < len) {
        return QSYSDB_ERR_BADJSON;
    }
    if (memcmp(p->pos, lit, len) != 0) {
        return QSYSDB_ERR_BADJSON;
    }
    p->pos += len;
    return QSYSDB_OK;
}

/*
 * Parse a JSON array
 */
static int parse_array(struct json_parser *p)
{
    int ret;

    if (p->pos >= p->end || *p->pos != '[') {
        return QSYSDB_ERR_BADJSON;
    }
    p->pos++;  /* Skip '[' */

    p->depth++;
    if (p->depth > p->max_depth) {
        return QSYSDB_ERR_BADJSON;  /* Too deeply nested */
    }

    skip_whitespace(p);

    /* Empty array */
    if (p->pos < p->end && *p->pos == ']') {
        p->pos++;
        p->depth--;
        return QSYSDB_OK;
    }

    /* Parse elements */
    while (1) {
        ret = parse_value(p);
        if (ret != QSYSDB_OK) {
            return ret;
        }

        skip_whitespace(p);

        if (p->pos >= p->end) {
            return QSYSDB_ERR_BADJSON;
        }

        if (*p->pos == ']') {
            p->pos++;
            p->depth--;
            return QSYSDB_OK;
        }

        if (*p->pos != ',') {
            return QSYSDB_ERR_BADJSON;
        }
        p->pos++;  /* Skip ',' */

        skip_whitespace(p);
    }
}

/*
 * Parse a JSON object
 */
static int parse_object(struct json_parser *p)
{
    int ret;

    if (p->pos >= p->end || *p->pos != '{') {
        return QSYSDB_ERR_BADJSON;
    }
    p->pos++;  /* Skip '{' */

    p->depth++;
    if (p->depth > p->max_depth) {
        return QSYSDB_ERR_BADJSON;  /* Too deeply nested */
    }

    skip_whitespace(p);

    /* Empty object */
    if (p->pos < p->end && *p->pos == '}') {
        p->pos++;
        p->depth--;
        return QSYSDB_OK;
    }

    /* Parse key-value pairs */
    while (1) {
        /* Key must be a string */
        ret = parse_string(p);
        if (ret != QSYSDB_OK) {
            return ret;
        }

        skip_whitespace(p);

        /* Colon separator */
        if (p->pos >= p->end || *p->pos != ':') {
            return QSYSDB_ERR_BADJSON;
        }
        p->pos++;

        skip_whitespace(p);

        /* Value */
        ret = parse_value(p);
        if (ret != QSYSDB_OK) {
            return ret;
        }

        skip_whitespace(p);

        if (p->pos >= p->end) {
            return QSYSDB_ERR_BADJSON;
        }

        if (*p->pos == '}') {
            p->pos++;
            p->depth--;
            return QSYSDB_OK;
        }

        if (*p->pos != ',') {
            return QSYSDB_ERR_BADJSON;
        }
        p->pos++;  /* Skip ',' */

        skip_whitespace(p);
    }
}

/*
 * Parse a JSON value
 */
static int parse_value(struct json_parser *p)
{
    skip_whitespace(p);

    if (p->pos >= p->end) {
        return QSYSDB_ERR_BADJSON;
    }

    switch (*p->pos) {
    case '{':
        return parse_object(p);
    case '[':
        return parse_array(p);
    case '"':
        return parse_string(p);
    case 't':
        return parse_literal(p, "true", 4);
    case 'f':
        return parse_literal(p, "false", 5);
    case 'n':
        return parse_literal(p, "null", 4);
    case '-':
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return parse_number(p);
    default:
        return QSYSDB_ERR_BADJSON;
    }
}

/*
 * Validate a JSON string
 *
 * Returns QSYSDB_OK if the input is valid JSON, QSYSDB_ERR_BADJSON otherwise.
 */
int qsysdb_json_validate(const char *json, size_t len)
{
    struct json_parser p = {
        .input = json,
        .end = json + len,
        .pos = json,
        .depth = 0,
        .max_depth = 64  /* Reasonable nesting limit */
    };

    if (json == NULL || len == 0) {
        return QSYSDB_ERR_INVALID;
    }

    int ret = parse_value(&p);
    if (ret != QSYSDB_OK) {
        return ret;
    }

    /* Check for trailing garbage */
    skip_whitespace(&p);
    if (p.pos != p.end) {
        return QSYSDB_ERR_BADJSON;
    }

    return QSYSDB_OK;
}

/*
 * Validate a null-terminated JSON string
 */
int qsysdb_json_validate_str(const char *json)
{
    if (json == NULL) {
        return QSYSDB_ERR_INVALID;
    }
    return qsysdb_json_validate(json, strlen(json));
}

/*
 * Get the type of a JSON value
 * Returns: 'o' object, 'a' array, 's' string, 'n' number, 't' true, 'f' false, '0' null
 */
char qsysdb_json_type(const char *json, size_t len)
{
    if (json == NULL || len == 0) {
        return '\0';
    }

    /* Skip leading whitespace */
    while (len > 0 && (*json == ' ' || *json == '\t' ||
                       *json == '\n' || *json == '\r')) {
        json++;
        len--;
    }

    if (len == 0) {
        return '\0';
    }

    switch (*json) {
    case '{':
        return 'o';
    case '[':
        return 'a';
    case '"':
        return 's';
    case 't':
        return 't';
    case 'f':
        return 'f';
    case 'n':
        return '0';
    case '-':
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return 'n';
    default:
        return '\0';
    }
}

/*
 * Escape a string for JSON encoding
 * Returns the number of bytes written (not including null terminator),
 * or -1 if the buffer is too small.
 */
int qsysdb_json_escape_string(const char *input, size_t input_len,
                              char *output, size_t output_size)
{
    size_t written = 0;

    if (output_size < 3) {  /* Need at least "" + null */
        return -1;
    }

    output[written++] = '"';

    for (size_t i = 0; i < input_len; i++) {
        unsigned char c = (unsigned char)input[i];
        const char *escape = NULL;
        char hex[7];

        switch (c) {
        case '"':  escape = "\\\""; break;
        case '\\': escape = "\\\\"; break;
        case '\b': escape = "\\b"; break;
        case '\f': escape = "\\f"; break;
        case '\n': escape = "\\n"; break;
        case '\r': escape = "\\r"; break;
        case '\t': escape = "\\t"; break;
        default:
            if (c < 0x20) {
                snprintf(hex, sizeof(hex), "\\u%04x", c);
                escape = hex;
            }
            break;
        }

        if (escape) {
            size_t elen = strlen(escape);
            if (written + elen + 2 > output_size) {
                return -1;
            }
            memcpy(output + written, escape, elen);
            written += elen;
        } else {
            if (written + 3 > output_size) {
                return -1;
            }
            output[written++] = (char)c;
        }
    }

    if (written + 2 > output_size) {
        return -1;
    }
    output[written++] = '"';
    output[written] = '\0';

    return (int)written;
}
