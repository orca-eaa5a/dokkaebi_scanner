import jsbeautifier

def beautify_js(js_script):
    opts = jsbeautifier.default_options()
    opts.indent_size = 4
    opts.space_in_empty_paren = True

    res = jsbeautifier.beautify(js_script, opts)

    return res