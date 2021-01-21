using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Contracts;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            this.tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto reg)
        {
            if (await UserExists(reg.Username))
            {
                return BadRequest("Username is taken.");
            }
            
            using var hmac = new HMACSHA512();
            var user = new AppUser{
                UserName = reg.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(reg.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto{
                Username = user.UserName,
                Token = this.tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
         public async Task<ActionResult<UserDto>> Login(LoginDto login)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(usr => usr.UserName == login.Username);
            if (user==null) return  Unauthorized("Invalid username");
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(login.Password));
            if(computedHash.SequenceEqual(user.PasswordHash)){
                return new UserDto{
                    Username = user.UserName,
                    Token = this.tokenService.CreateToken(user)
                };
            } else {
                return Unauthorized("Invalid password");
            }
        }

        private async Task<bool> UserExists(string username) 
        {
            return await _context.Users.AnyAsync( usr => usr.UserName == username.ToLower());
        }
    }
}