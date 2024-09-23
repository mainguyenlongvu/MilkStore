using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Repositories.Entity;

namespace MilkStore.Repositories.Context
{
    public class DatabaseContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid, ApplicationUserClaims, ApplicationUserRoles, ApplicationUserLogins, ApplicationRoleClaims, ApplicationUserTokens>
    {
        public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options) { }
        #region Entity
        // user
        public virtual DbSet<ApplicationUser> ApplicationUsers => Set<ApplicationUser>();
        public virtual DbSet<ApplicationRole> ApplicationRoles => Set<ApplicationRole>();
        public virtual DbSet<ApplicationUserClaims> ApplicationUserClaims => Set<ApplicationUserClaims>();
        public virtual DbSet<ApplicationUserRoles> ApplicationUserRoles => Set<ApplicationUserRoles>();
        public virtual DbSet<ApplicationUserLogins> ApplicationUserLogins => Set<ApplicationUserLogins>();
        public virtual DbSet<ApplicationRoleClaims> ApplicationRoleClaims => Set<ApplicationRoleClaims>();
        public virtual DbSet<ApplicationUserTokens> ApplicationUserTokens => Set<ApplicationUserTokens>();
        public virtual DbSet<Products> Products => Set<Products>();
        public virtual DbSet<Post> Posts => Set<Post>();
        public virtual DbSet<Order> Orders => Set<Order>();
        public virtual DbSet<Review> Reviews => Set<Review>();
        public virtual DbSet<OrderDetails> OrderDetails => Set<OrderDetails>();
        public virtual DbSet<Voucher> Vouchers => Set<Voucher>();
        public virtual DbSet<PreOrders> PreOrders => Set<PreOrders>();
        public virtual DbSet<Category> Category => Set<Category>();
        public virtual DbSet<Gift> Gifts => Set<Gift>();
        #endregion
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.Entity<Post>()
            //    .HasMany(p => p.Products)
            //    .WithMany(p => p.Posts)
            //    .UsingEntity(j => j.ToTable("PostProducts"));  // Custom join table
            //Add FK_Order_Voucher
            modelBuilder.Entity<Order>()
                .HasOne(o => o.Voucher)
                .WithMany(v => v.Orders)
                .HasForeignKey(o => o.VoucherId)
                .OnDelete(DeleteBehavior.NoAction);

            //Add FK_Order_OrderDetails
            modelBuilder.Entity<Order>()
                .HasMany(o => o.OrderDetailss)
                .WithOne(od => od.Order)
                .HasForeignKey(od => od.OrderID)
                .OnDelete(DeleteBehavior.Cascade);


            modelBuilder.Entity<Order>()
            .HasOne(o => o.User)
            .WithMany(u => u.Orders)
            .HasForeignKey(o => o.UserId);

            //Add FK_Product_OrderDetails
            modelBuilder.Entity<Products>()
               .HasMany(o => o.OrderDetail)
               .WithOne(p => p.Products)
               .HasForeignKey(p => p.ProductID)
               .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ApplicationUserLogins>()
                .HasKey(l => new { l.UserId, l.LoginProvider, l.ProviderKey });
            modelBuilder.Entity<ApplicationUserRoles>()
                .HasKey(ur => new { ur.UserId, ur.RoleId });
            modelBuilder.Entity<ApplicationUserTokens>()
            .HasKey(t => new { t.UserId, t.LoginProvider, t.Name });
        }
    }
}
