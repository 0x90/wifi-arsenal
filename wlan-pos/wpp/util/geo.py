#!/usr/bin/env python
# A set of functions for performing various geographic calculations.
import math
import numpy as np

from wpp.config import RADIUS

eq_rad    = 6378.137 #eq radius in km
polar_rad = 6356.752 #polar radius in km


#def mercator_coords(geo_pt, center):
#    '''
#    Projects the given coordinates using Mercator projection
#    with respect to `center`.
#    '''
#
#    x = geo_pt[0: , :1] - center[0]
#    y = sp.arctanh(np.sin(geo_pt[0 : , 1:]*(np.pi/360)))
#    
#    return sp.hstack((x,y))


def dist_km(lon1, lat1, lon2, lat2):
   '''
   Given a set of geo coordinates (in degrees) it will return the distance in km
   '''

   #convert to radians
   lon1 = lon1*2*np.pi/360
   lat1 = lat1*2*np.pi/360
   lon2 = lon2*2*np.pi/360
   lat2 = lat2*2*np.pi/360

   R = earth_radius((lat1+lat2)/2) #km

   #haversine formula - angles in radians
   deltaLon = np.abs(lon1-lon2)
   deltaLat = np.abs(lat1-lat2)

   dOverR = haver_sin(deltaLat) + np.cos(lat1)*np.cos(lat2)*haver_sin(deltaLon)

   return R * arc_haver_sin(dOverR)


def earth_radius(lat):
   '''
   Given a latitude in radias returns earth radius in km
   '''

   top = (eq_rad**2 * np.cos(lat))**2 + (polar_rad**2 * np.sin(lat))**2
   bottom = (eq_rad * np.cos(lat))**2 + (polar_rad * np.sin(lat))**2
   
   return np.sqrt(top/bottom)


def haver_sin(x):
   return np.sin(x/2) ** 2


def arc_haver_sin(x):
   return 2*np.arcsin(np.sqrt(x))


def dist_unit(lat1, long1, lat2, long2):

    # Convert latitude and longitude to 
    # spherical coordinates in radians.
    degrees_to_radians = math.pi/180.0
        
    # phi = 90 - latitude
    phi1 = (90.0 - lat1)*degrees_to_radians
    phi2 = (90.0 - lat2)*degrees_to_radians
        
    # theta = longitude
    theta = (long1-long2)*degrees_to_radians
    #theta1 = long1*degrees_to_radians
    #theta2 = long2*degrees_to_radians
        
    # Compute spherical distance from spherical coordinates.
        
    # For two locations in spherical coordinates 
    # (1, theta, phi) and (1, theta, phi)
    # cosine( arc length ) = 
    #    sin phi sin phi' cos(theta-theta') + cos phi cos phi'
    # distance = rho * arc length
    
    cos = (math.sin(phi1)*math.sin(phi2)*math.cos(theta) + 
           math.cos(phi1)*math.cos(phi2))
    arc = math.acos( cos )

    # Remember to multiply arc by the radius of the earth 
    # in your favorite set of units to get length.
    return arc


if __name__ == '__main__':
    lat1, lon1, lat2, lon2 = 39.88726,116.3442,39.89711,116.3500
    lat3, lon3, lat4, lon4 = 39.902157500000001, 116.3508545,39.89967,116.35247

    print 'dist_unit: ', dist_unit(lat1, lon1, lat2, lon2)*(RADIUS)
    print '  dist_km: ', dist_km(lon1, lat1, lon2, lat2)*1000

    print 'dist_unit: ', dist_unit(lat3, lon3, lat4, lon4)*(RADIUS)
    print '  dist_km: ', dist_km(lon3, lat3, lon4, lat4)*1000
