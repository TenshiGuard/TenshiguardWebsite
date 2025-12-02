from app import create_app

app = create_app()

with app.app_context():
    print(f"{'Endpoint':<50} {'Methods':<20} {'Rule'}")
    print("-" * 80)
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        print(f"{rule.endpoint:<50} {methods:<20} {rule}")
