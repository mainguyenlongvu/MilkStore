using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Repositories.Context;
using MilkStore.Repositories.Entity;
using MilkStore.Services;
using MilkStore.Services.EmailSettings;
using MilkStore.Services.Mapping;
using MilkStore.Services.Service;

namespace MilkStore.API
{
    public static class DependencyInjection
    {
        public static void AddConfig(this IServiceCollection services, IConfiguration configuration)
        {

            services.AddCorsConfig();
            services.ConfigRoute();
            services.AddSignalConfig();
            services.AddConfigTimeToken();
            services.AddSwaggerUIAuthentication();
            services.AddMemoryCache();
            services.AddDatabase(configuration);
            services.AddIdentity();
            services.AddInfrastructure(configuration);
            services.AddServices();
            //services.AddAuthenticationGoogle();
            services.AddAuthenticationBearer(configuration);
            services.AddAutoMapperConfig();
            services.AddEmailConfig(configuration);
            services.ConfigureSession();
        }
        public static void AddSignalConfig(this IServiceCollection services)
        {
            services.AddSignalR();
        }
        public static void AddAuthenticationBearer(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new Exception("JWT_ISSUER is not set"),
                        ValidAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new Exception("JWT_AUDIENCE is not set"),
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_KEY") ?? throw new Exception("JWT_KEY is not set")))
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = context =>
                        {
                            var accessToken = context.Request.Query["access_token"];
                            var path = context.HttpContext.Request.Path;
                            if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/chatHub"))
                            {
                                if (accessToken.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                                {
                                    context.Token = accessToken.ToString().AsSpan(7).Trim().ToString();
                                }
                                else
                                {
                                    context.Token = accessToken;
                                }
                            }
                            return Task.CompletedTask;
                        }
                    };
                });

        }
        public static void ConfigRoute(this IServiceCollection services)
        {
            services.Configure<RouteOptions>(options =>
            {
                options.LowercaseUrls = true;
            });
        }
        public static void AddDatabase(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<DatabaseContext>(options =>
            {
                options.UseLazyLoadingProxies()
                       .UseSqlServer(configuration.GetConnectionString("DefaultConnection"),
                                     sqlServerOptions => sqlServerOptions.EnableRetryOnFailure(
                                         maxRetryCount: 5,
                                         maxRetryDelay: TimeSpan.FromSeconds(10),
                                         errorNumbersToAdd: null));
            });
        }

        public static void AddIdentity(this IServiceCollection services)
        {
            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
            })
             .AddEntityFrameworkStores<DatabaseContext>()
             .AddDefaultTokenProviders();
        }
        public static void AddServices(this IServiceCollection services)
        {
            services.AddScoped<ChatHubService>();
            services.AddScoped<IAuthService, AuthService>();
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IPostService, PostService>();
            services.AddScoped<IOrderService, OrderService>();
            services.AddScoped<IOrderDetailsService, OrderDetailsService>();
            services.AddScoped<IVoucherService, VoucherService>();
            services.AddScoped<IReviewsService, ReviewsService>();
            services.AddScoped<IPreOrdersService, PreOrdersService>();
            services.AddScoped<IProductsService, ProductsService>();
            services.AddScoped<ICategoryService, CategoryService>();
            services.AddScoped<IGiftService, GiftService>();
            services.AddScoped<IOrderGiftService, OrderGiftService>();
            services.AddScoped<IOrderDetailGiftService, OrderDetailGiftService>();
            services.AddScoped<IEmailService, EmailService>();
            services.AddScoped<IPaymentService, PaymentService>();
            services.AddScoped<IRoleService, RoleService>();
            services.AddScoped<IStatisticalService, StatisticalService>();
            services.AddScoped<IStatisticalProductService, StatisticalProductService>();
            services.AddScoped<ITransactionService, TransactionService>();
            services.AddSingleton<ICloudinaryService,CloudinaryService>();
            services.AddHttpContextAccessor();
        }


        public static void AddAutoMapperConfig(this IServiceCollection services)
        {
            services.AddAutoMapper(typeof(MappingProfile));
        }
        public static void AddEmailConfig(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<EmailSettings>(configuration.GetSection("EmailSettings"));
        }

        public static void AddSwaggerUIAuthentication(this IServiceCollection services)
        {
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "MilkStore.API", Version = "v1" });
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
                        },
                        Array.Empty<string>()
                    }
                });
            });
        }
        public static void AddCorsConfig(this IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder =>
                    {
                        builder.WithOrigins("*")
                               .AllowAnyHeader()
                               .AllowAnyMethod();
                    });
            });
        }
        public static void AddAuthenticationGoogle(this IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddGoogle(option =>
            {
                option.ClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENTID") ?? throw new Exception("GOOGLE_CLIENTID is not set");
                option.ClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENTSECRET") ?? throw new Exception("GOOGLE_CLIENTSECRET is not set");
                option.CallbackPath = "/signin-google";
                option.SaveTokens = true;
            });
        }
        public static void AddConfigTimeToken(this IServiceCollection services)
        {
            services.Configure<DataProtectionTokenProviderOptions>(options =>
                    options.TokenLifespan = TimeSpan.FromMinutes(30));
        }
        public static void ConfigureSession (this IServiceCollection services)
        {            
            services.AddDistributedMemoryCache(); // Cấu hình cache cho session
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30); // Thời gian timeout cho session
                options.Cookie.HttpOnly = true; // Cookie chỉ có thể truy cập từ server
                options.Cookie.IsEssential = true; // Cookie cần thiết cho ứng dụng
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.None;
            });
        }
    }
}
