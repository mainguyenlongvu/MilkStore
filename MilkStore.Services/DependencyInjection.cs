using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Repositories.UOW;

namespace MilkStore.Services
{
    public static class DependencyInjection
    {
        public static void AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddRepositories();
        }
        public static void AddRepositories(this IServiceCollection services)
        {
            services.AddScoped<IUnitOfWork, UnitOfWork>();
        }
    }
}
