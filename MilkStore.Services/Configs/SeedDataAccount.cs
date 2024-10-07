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
            string nameAdmin = "Admin";


            ApplicationUser? adminAccount = await userManager.FindByEmailAsync(emailAdmin);
            if (adminAccount is null)
            {
                ApplicationUser? newAccount = new ApplicationUser
                {
                    UserName = emailAdmin,
                    ManagerId = null,
                    Email = emailAdmin,
                    EmailConfirmed = true,
                    Name = nameAdmin
                };
                await userManager.CreateAsync(newAccount, passwordAdmin);
                await userManager.AddToRoleAsync(newAccount, "Admin");
            }

            if (!await roleManager.RoleExistsAsync("Member"))
            {
                await roleManager.CreateAsync(new ApplicationRole { Name = "Member" });
            }
            string emailMember = "Member@gmail.com";
            string passwordMember = "Member123*";
            string nameMem = "Member 1";

            ApplicationUser? memberAccount = await userManager.FindByEmailAsync(emailMember);
            if (memberAccount is null)
            {
                ApplicationUser? newAccount = new ApplicationUser
                {
                    UserName = emailMember,

                    ManagerId = null,
                    Email = emailMember,
                    EmailConfirmed = true,
                    Name = nameMem,
                };
                await userManager.CreateAsync(newAccount, passwordMember);
                await userManager.AddToRoleAsync(newAccount, "Member");
            }
            if (!await roleManager.RoleExistsAsync("Staff"))
            {
                await roleManager.CreateAsync(new ApplicationRole { Name = "Staff" });
            }
            string emailStaff = "Staff@gmail.com";
            string passwordStaff = "Staff123*";
            string name1 = "Staff1";
            ApplicationUser? staffAccount = await userManager.FindByEmailAsync(emailStaff);
            if (staffAccount is null)
            {
                ApplicationUser? newAccount = new ApplicationUser
                {
                    UserName = emailStaff,

                    ManagerId = null,
                    Email = emailStaff,
                    EmailConfirmed = true,
                    Name = name1,
                };
                await userManager.CreateAsync(newAccount, passwordStaff);
                await userManager.AddToRoleAsync(newAccount, "Staff");
            }
            string emailStaff2 = "Staff2@gmail.com";
            string passwordStaff2 = "Staff123*";
            string name2 = "Staff2";
            ApplicationUser? staffAccount2 = await userManager.FindByEmailAsync(emailStaff);
            if (staffAccount2 is null)
            {
                ApplicationUser? newAccount = new ApplicationUser
                {
                    UserName = emailStaff2,
                    Email = emailStaff,
                    EmailConfirmed = true,
                    Name = name2,
                };
                await userManager.CreateAsync(newAccount, passwordStaff2);
                await userManager.AddToRoleAsync(newAccount, "Staff");
            }
        }
    }
}