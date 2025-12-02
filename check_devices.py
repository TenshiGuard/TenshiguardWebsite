from app import create_app
from app.models.device import Device

def check_devices():
    app = create_app()
    with app.app_context():
        count = Device.query.count()
        print(f"Total Devices: {count}")
        devices = Device.query.all()
        for d in devices:
            print(f"Device: {d.device_name} ({d.mac}) - ID: {d.id}")

if __name__ == "__main__":
    check_devices()
