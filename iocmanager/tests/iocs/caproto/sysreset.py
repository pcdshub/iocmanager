from caproto.server import PVGroup, ioc_arg_parser, pvproperty, run


class TestIOC(PVGroup):
    sys_reset = pvproperty(
        name="SYSRESET",
        value=0,
    )


if __name__ == "__main__":
    ioc_options, run_options = ioc_arg_parser(
        default_prefix="IOC:PYTEST:01:",
        desc="Test IOC",
    )
    ioc = TestIOC(**ioc_options)
    run(ioc.pvdb, **run_options)
