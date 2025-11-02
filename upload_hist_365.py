import os
import csv
from datetime import datetime
from app import app
from models import db, HistData365

def upload_csv_to_hist_365(csv_file_path):
    """Upload CSV data to hist_data_365 table"""
    
    with app.app_context():
        try:
            with open(csv_file_path, 'r') as file:
                csv_reader = csv.DictReader(file)
                
                records_added = 0
                records_skipped = 0
                batch_size = 1000
                
                for row in csv_reader:
                    try:
                        # Parse dates
                        date_obj = datetime.strptime(row['Date'], '%Y-%m-%d').date()
                        datetime_obj = datetime.strptime(row['Datetime'], '%Y-%m-%d %H:%M:%S')
                        
                        # Handle Created At - use current time if empty
                        if row['Created At'] and row['Created At'].strip():
                            try:
                                created_at_obj = datetime.strptime(row['Created At'], '%Y-%m-%d %H:%M:%S.%f')
                            except:
                                created_at_obj = datetime.strptime(row['Created At'], '%Y-%m-%d %H:%M:%S')
                        else:
                            created_at_obj = datetime.utcnow()
                        
                        # Check if record already exists
                        existing = HistData365.query.filter_by(
                            symbol=row['Symbol'],
                            date=date_obj,
                            timeframe=row['Timeframe']
                        ).first()
                        
                        if existing:
                            # Update existing record
                            existing.datetime_stamp = datetime_obj
                            existing.open = float(row['Open'])
                            existing.high = float(row['High'])
                            existing.low = float(row['Low'])
                            existing.close = float(row['Close'])
                            existing.volume = int(float(row['Volume']))
                            existing.source = row['Source']
                            existing.day_of_week = row['Day of Week']
                            records_skipped += 1
                        else:
                            # Create new record
                            record = HistData365(
                                symbol=row['Symbol'],
                                date=date_obj,
                                datetime_stamp=datetime_obj,
                                open=float(row['Open']),
                                high=float(row['High']),
                                low=float(row['Low']),
                                close=float(row['Close']),
                                volume=int(float(row['Volume'])),
                                timeframe=row['Timeframe'],
                                source=row['Source'],
                                day_of_week=row['Day of Week'],
                                created_at=created_at_obj
                            )
                            db.session.add(record)
                            records_added += 1
                        
                        # Commit in batches
                        if (records_added + records_skipped) % batch_size == 0:
                            db.session.commit()
                            print(f"✓ Processed {records_added + records_skipped} records (Added: {records_added}, Updated: {records_skipped})...")
                            
                    except Exception as e:
                        records_skipped += 1
                        print(f"⚠ Error for {row.get('Symbol', 'Unknown')}: {str(e)}")
                        continue
                
                # Commit any remaining records
                db.session.commit()
                
                print(f"\n✅ Upload complete!")
                print(f"   Records added: {records_added}")
                print(f"   Records skipped: {records_skipped}")
                
        except Exception as e:
            print(f"❌ Error uploading CSV: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    csv_path = "attached_assets/hist_data_365 (2)_1760536211792.csv"
    print(f"Starting upload from {csv_path}...")
    upload_csv_to_hist_365(csv_path)
