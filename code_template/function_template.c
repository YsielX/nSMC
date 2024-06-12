void check_{algorithm}_{key}_{iv}() {{
    char selection[16];
    scanf("%{input_length}s", selection);
    if (!strncmp(selection, "{random_str[0]}", {input_length})) {{
        decrypt_{next_algorithm[0]}((unsigned char *)check_{next_algorithm[0]}_{next_key[0]}_{next_iv[0]}, "{next_key_decode[0]}", "{next_iv_decode[0]}");
        check_{next_algorithm[0]}_{next_key[0]}_{next_iv[0]}();
    }} else if (!strncmp(selection, "{random_str[1]}", {input_length})) {{
        decrypt_{next_algorithm[1]}((unsigned char *)check_{next_algorithm[1]}_{next_key[1]}_{next_iv[1]}, "{next_key_decode[1]}", "{next_iv_decode[1]}");
        check_{next_algorithm[1]}_{next_key[1]}_{next_iv[1]}();
    }} else if (!strncmp(selection, "{random_str[2]}", {input_length})) {{
        decrypt_{next_algorithm[2]}((unsigned char *)check_{next_algorithm[2]}_{next_key[2]}_{next_iv[2]}, "{next_key_decode[2]}", "{next_iv_decode[2]}");
        check_{next_algorithm[2]}_{next_key[2]}_{next_iv[2]}();
    }} else if (!strncmp(selection, "{random_str[3]}", {input_length})) {{
        decrypt_{next_algorithm[3]}((unsigned char *)check_{next_algorithm[3]}_{next_key[3]}_{next_iv[3]}, "{next_key_decode[3]}", "{next_iv_decode[3]}");
        check_{next_algorithm[3]}_{next_key[3]}_{next_iv[3]}();
    }} else if (!strncmp(selection, "{random_str[4]}", {input_length})) {{
        decrypt_{next_algorithm[4]}((unsigned char *)check_{next_algorithm[4]}_{next_key[4]}_{next_iv[4]}, "{next_key_decode[4]}", "{next_iv_decode[4]}");
        check_{next_algorithm[4]}_{next_key[4]}_{next_iv[4]}();
    }} else if (!strncmp(selection, "{random_str[5]}", {input_length})) {{
        decrypt_{next_algorithm[5]}((unsigned char *)check_{next_algorithm[5]}_{next_key[5]}_{next_iv[5]}, "{next_key_decode[5]}", "{next_iv_decode[5]}");
        check_{next_algorithm[5]}_{next_key[5]}_{next_iv[5]}();
    }} else {{
        printf("Invalid selection\n");
    }}
}}
