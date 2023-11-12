using hotelBooking.Models;
using HotelBookingAPI.Interfaces;
using HotelBookingAPI.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson;
using MongoDB.Driver;
using System;

namespace HotelBookingAPI.Services
{
    public class UserService : IUser
    {
        private readonly IConfiguration _configuration;
        private readonly IMongoCollection<User> _userCollection;
        public UserService(IConfiguration configuration, IMongoClient client)
        {
            var database = client.GetDatabase("HotelRoomsDB");
            _userCollection = database.GetCollection<User>("Users");
            _configuration = configuration;
        }
        public async Task<User?> Register(UserLogin user)
        {
            var result = await _userCollection.Find(u => u.Username == user.Username).FirstOrDefaultAsync();
            if (result is null)
            {
                User newUser = new()
                {
                    Username = user.Username,
                    Password = HashPassword(user.Password),
                    Role = Role.User
                };
                await _userCollection.InsertOneAsync(newUser);
                return newUser;
            }
            return null;
        }
        public async Task<string?> Login(UserLogin user)
        {
            var result = await GetUserByUsername(user);
            if (result is null)
            {
                return null;
            }
            if (VerifyPassword(user.Password,result.Password))
            {
                User newUser = new()
                {
                    Username = user.Username,
                    Password = HashPassword(user.Password),
                    Role = result.Role
                };
                string token = CreateToken(newUser);
                return token;
            }
            return null;
        }
        public async Task<string?> CancelBooking(CancellationInfo cancellationInfo)
        {
            var filter = Builders<User>.Filter.Eq("UserID",cancellationInfo.UserID);
            var update = Builders<User>.Update.PullFilter(x => x.BookedRooms, y => y.RoomID == cancellationInfo.RoomID);
            await _userCollection.UpdateOneAsync(filter, update);
            return null;
        }
        private static string HashPassword(string password, byte[]? salt = null, bool needsOnlyHash = false)
        {
            if (salt == null || salt.Length != 16)
            {
                salt = new byte[128 / 8];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(salt);
            }

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));
            if (needsOnlyHash) return hashed;
            return $"{hashed}:{Convert.ToBase64String(salt)}";
        }
        private static bool VerifyPassword(string password, string passwordInDB)
        {
            var passwordAndSalt = passwordInDB.Split(':');
            if (passwordAndSalt == null || passwordAndSalt.Length != 2)
                return false;
            var salt = Convert.FromBase64String(passwordAndSalt[1]);
            if (salt == null)
                return false;
            var hashOfpasswordToCheck = HashPassword(password, salt, true);
            if (String.Compare(passwordAndSalt[0], hashOfpasswordToCheck) == 0)
            {
                return true;
            }
            return false;
        }
    }
}
