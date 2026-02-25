import sys
import pandas as pd

def main():
    print("Starting Aegis Python Analyzer...")
    print("Waiting for data stream...")

    # We read from Standard Input (stdin) line by line
    for line in sys.stdin:
        try:
            # Clean the line (remove whitespace/newlines)
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Split the CSV data: timestamp, src, dst, length
            parts = line.split(',')
            
            if len(parts) == 4:
                timestamp, src_ip, dst_ip, length = parts
                
                # convert length to int for logic
                length = int(length)
                
                # --- SIMPLE LOGIC (Placeholder for AI) ---
                # Let's flag any packet larger than 1000 bytes as "Jumbo"
                # and anything else as "Standard"
                pkt_type = "STANDARD"
                if length > 1000:
                    pkt_type = "JUMBO - MONITOR"
                
                # Print a clean formatted output
                print(f"[Aegis] {src_ip} -> {dst_ip} | Size: {length} | Type: {pkt_type}")
                
        except ValueError:
            # In case a malformed line comes through
            continue
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()