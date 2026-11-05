from ids.ids_config import external_net_excludes_home, parse_network_variables


def test_snort_lua_variables_are_read():
    text = "-- HOME_NET = '10.0.0.0/8'\nHOME_NET = 'any'\nEXTERNAL_NET = 'any'\n"
    assert parse_network_variables("snort", text) == {
        "HOME_NET": "any", "EXTERNAL_NET": "any",
    }


def test_suricata_yaml_variables_skip_commented_examples():
    text = (
        '    HOME_NET: "[192.168.50.0/24]"\n'
        '    #HOME_NET: "[10.0.0.0/8]"\n'
        '    EXTERNAL_NET: "!$HOME_NET"\n'
        '    #EXTERNAL_NET: "any"\n'
    )
    variables = parse_network_variables("suricata", text)
    assert variables == {"HOME_NET": "[192.168.50.0/24]", "EXTERNAL_NET": "!$HOME_NET"}
    assert external_net_excludes_home(variables)


def test_any_external_net_does_not_exclude_home():
    assert not external_net_excludes_home({"EXTERNAL_NET": "any"})
