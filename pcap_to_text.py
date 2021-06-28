from pylibpcap.pcap import rpcap

for _, _, packet in rpcap("data.pcap"):
    offset = 42

    # Header
    session = packet[offset + 0 : offset + 10].decode("utf8")
    next_seq_number = int.from_bytes(packet[offset + 10 : offset + 18], byteorder='big')
    msg_count = int.from_bytes(packet[offset + 18 : offset + 20], byteorder='big')

    offset += 20
    for i in range(msg_count):
        length = int.from_bytes(packet[offset : offset + 2], byteorder='big')
        offset += 2
        msg_type = packet[offset + 0 : offset + 1].decode("utf8")
        time_stamp = int.from_bytes(packet[offset + 1 : offset + 9], byteorder='big')

        if msg_type == "C":
            # Quotation Message
            stock_symbol                          = packet[offset + 9 : offset + 19].decode("utf8")
            nasdaq_canada_best_bid_price          = int.from_bytes(packet[offset + 19 : offset + 27], byteorder='big') / 100000000
            nasdaq_canada_best_bid_size           = int.from_bytes(packet[offset + 27 : offset + 31], byteorder='big')
            nasdaq_cxc_best_bid_size              = int.from_bytes(packet[offset + 31 : offset + 35], byteorder='big')
            nasdaq_cx2_best_bid_size              = int.from_bytes(packet[offset + 35 : offset + 39], byteorder='big')
            nasdaq_canada_best_ask_price          = int.from_bytes(packet[offset + 39 : offset + 47], byteorder='big') / 100000000
            nasdaq_canada_best_ask_size           = int.from_bytes(packet[offset + 47 : offset + 51], byteorder='big')
            nasdaq_cxc_best_ask_size              = int.from_bytes(packet[offset + 51 : offset + 55], byteorder='big')
            nasdaq_cx2_best_ask_size              = int.from_bytes(packet[offset + 55 : offset + 59], byteorder='big')
        
        elif msg_type == "T":
            # Trade Report Message
            originating_market_center_identifier = packet[offset + 9 : offset + 10].decode("utf8")
            stock_symbol                         = packet[offset + 10 : offset + 20].decode("utf8")
            trade_number                         = int.from_bytes(packet[offset + 20 : offset + 24], byteorder='big')
            trade_price                          = int.from_bytes(packet[offset + 24 : offset + 32], byteorder='big') / 100000000
            trade_size                           = int.from_bytes(packet[offset + 32 : offset + 36], byteorder='big')
            broker                               = packet[offset + 36 : offset + 39].decode("utf8")
            contra_broker                        = packet[offset + 39 : offset + 42].decode("utf8")
            sale_condition_modifier_lvl_1        = packet[offset + 42 : offset + 43].decode("utf8")
            sale_condition_modifier_lvl_2        = packet[offset + 43 : offset + 44].decode("utf8")
            sale_condition_modifier_lvl_3        = packet[offset + 44 : offset + 45].decode("utf8")
            sale_condition_modifier_lvl_4        = packet[offset + 45 : offset + 46].decode("utf8")
        
        elif msg_type == "X":
            # Trade Break Message
            trade_control_number                 = int.from_bytes(packet[offset + 9 : offset + 13], byteorder='big')
            originating_market_center_identifier = packet[offset + 13 : offset + 14].decode("utf8")
        
        elif msg_type == "Z":
            # Trade Correction Message
            originating_market_center_identifier = packet[offset + 9 : offset + 10].decode("utf8")
            stock_symbol                         = packet[offset + 10 : offset + 20].decode("utf8")
            original_trade_number                = int.from_bytes(packet[offset + 20 : offset + 24], byteorder='big')
            original_trade_price                 = int.from_bytes(packet[offset + 24 : offset + 32], byteorder='big') / 100000000
            original_trade_size                  = int.from_bytes(packet[offset + 32 : offset + 36], byteorder='big')
            corrected_trade_price                = int.from_bytes(packet[offset + 36 : offset + 44], byteorder='big') / 100000000
            corrected_trade_size                 = int.from_bytes(packet[offset + 44 : offset + 48], byteorder='big')

        elif msg_type == "S":
            # System Event Message
            originating_market_center_identifier = packet[offset + 9 : offset + 10].decode("utf8")
            event_code                           = packet[offset + 10 : offset + 11].decode("utf8")

        elif msg_type == "R":
            # Stock Directory Message
            stock_symbol                         = packet[offset + 9 : offset + 19].decode("utf8")
            stock_display_name                   = packet[offset + 19 : offset + 59].decode("utf8")
            listing_market                       = packet[offset + 59 : offset + 60].decode("utf8")
            board_lot_size                       = int.from_bytes(packet[offset + 60 : offset + 64], byteorder='big')
            currency                             = packet[offset + 64 : offset + 65].decode("utf8")

        elif msg_type == "H":
            # Stock Status Message
            stock_symbol                         = packet[offset + 9 : offset + 19].decode("utf8")
            market                               = packet[offset + 19 : offset + 20].decode("utf8")
            system_status                        = packet[offset + 20 : offset + 21].decode("utf8")

        offset += length