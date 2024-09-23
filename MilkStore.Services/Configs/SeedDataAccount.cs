using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Repositories.Entity;

namespace MilkStore.Services.Configs
{
    public static class SeedDataAccount
    {
        public static async Task SeedAsync(IServiceProvider serviceProvider)
        {
            UserManager<ApplicationUser> userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            RoleManager<ApplicationRole> roleManager = serviceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new ApplicationRole { Name = "Admin" });
            }
            string emailAdmin = "Admin@gmail.com";
            string passwordAdmin = "Admin123.";

            ApplicationUser? adminAccount = await userManager.FindByEmailAsync(emailAdmin);
            if (adminAccount is null)
            {
                ApplicationUser? newAccount = new ApplicationUser
                {
                    UserName = emailAdmin,
                    Email = emailAdmin,
                    EmailConfirmed = true
                };
                await userManager.CreateAsync(newAccount, passwordAdmin);
                await userManager.AddToRoleAsync(newAccount, "Admin");
            }

            if (!await roleManager.RoleExistsAsync("Staff"))
            {
                await roleManager.CreateAsync(new ApplicationRole { Name = "Staff" });
            }
            string emailStaff = "Staff@gmail.com";
            string passwordStaff = "Staff123*";
            ApplicationUser? staffAccount = await userManager.FindByEmailAsync(emailStaff);
            if (staffAccount is null)
            {
                ApplicationUser? newAccount = new ApplicationUser
                {
                    UserName = emailStaff,
                    Email = emailStaff,
                    EmailConfirmed = true
                };
                await userManager.CreateAsync(newAccount, passwordStaff);
                await userManager.AddToRoleAsync(newAccount, "Staff");
            }
        }
    }
}