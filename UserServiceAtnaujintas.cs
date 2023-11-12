using hotelBooking.Models;
using HotelBookingAPI.Interfaces;
using HotelBookingAPI.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace HotelBookingAPI.Services
{
    public class UserService : IUserService
    {
        private readonly IConfiguration _configuration;
        private readonly IMongoCollection<User> _userCollection;
        private const int SaltSize = 128 / 8; // 16 bytes
        private const int IterationCount = 10000;
        private const int HashSize = 256 / 8; // 32 bytes

        public UserService(IConfiguration configuration, IMongoClient client)
        {
            _configuration = configuration;
            var database = client.GetDatabase(_configuration["DatabaseSettings:DatabaseName"]);
            _userCollection = database.GetCollection<User>(_configuration["DatabaseSettings:UserCollectionName"]);
        }

        public async Task<User?> Register(UserLogin user)
        {
            var existingUser = await GetUserByUsername(user.Username);
            if (existingUser is null)
            {
                var newUser = new User
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
            var userFromDb = await GetUserByUsername(user.Username);
            if (userFromDb != null && IsPasswordMatch(user.Password, userFromDb.Password))
            {
                string token = CreateToken(userFromDb);
                return token;
            }
            return null;
        }

        public async Task<User?> GetUserByUsername(string username)
        {
            return await _userCollection.Find(u => u.Username == username).FirstOrDefaultAsync();
        }

        public async Task<bool> CancelBooking(CancellationInfo cancellationInfo)
        {
            var filter = Builders<User>.Filter.Eq("UserID", cancellationInfo.UserID);
            var update = Builders<User>.Update.PullFilter(x => x.BookedRooms, y => y.RoomID == cancellationInfo.RoomID);
            var result = await _userCollection.UpdateOneAsync(filter, update);
            return result.IsAcknowledged && result.ModifiedCount > 0;
        }

        private static string HashPassword(string password)
        {
            byte[] salt = GenerateSalt();
            return ComputeHash(password, salt) + ":" + Convert.ToBase64String(salt);
        }

        private static bool IsPasswordMatch(string password, string storedHash)
        {
            var parts = storedHash.Split(':');
            if (parts.Length != 2)
                return false;

            var salt = Convert.FromBase64String(parts[1]);
            return ComputeHash(password, salt) == parts[0];
        }

        private static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SaltSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            return salt;
        }

        private static string ComputeHash(string password, byte[] salt)
        {
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password,
                salt,
                KeyDerivationPrf.HMACSHA256,
                IterationCount,
                HashSize));
        }

        private string CreateToken(User user)
        {
            // Implement token creation logic
            throw new NotImplementedException();
        }
    }
}
