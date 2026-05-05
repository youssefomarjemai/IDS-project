import geoip2.database
import os

DB_PATH = 'data/GeoLite2-City.mmdb'

def get_location(ip):
    try:
        if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('127.'):
            return {
                'country': 'Local Network',
                'city': 'Local',
                'lat': 0,
                'lon': 0
            }

        reader = geoip2.database.Reader(DB_PATH)
        response = reader.city(ip)
        reader.close()

        return {
            'country': response.country.name or 'Unknown',
            'city': response.city.name or 'Unknown',
            'lat': response.location.latitude or 0,
            'lon': response.location.longitude or 0
        }
    except:
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'lat': 0,
            'lon': 0
        }