from pycomm3.slc import SLCDriver

with SLCDriver("198.168.10.3") as slc:
    print(slc.get_plc_info())