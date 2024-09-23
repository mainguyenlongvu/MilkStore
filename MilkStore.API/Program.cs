using AutoMapper;
using dotenv.net;
using Microsoft.EntityFrameworkCore;
using MilkStore.API;
using MilkStore.Contract.Repositories;
using MilkStore.Contract.Services.Interface;
using MilkStore.Repositories.Context;
using MilkStore.Repositories.UOW;
using MilkStore.Services.Configs;
using MilkStore.Services.Service;

DotEnv.Load();

var builder = WebApplication.CreateBuilder(args);

// config appsettings by env
builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
    });



builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddConfig(builder.Configuration);
WebApplication? app = builder.Build();

// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseCors("AllowAllOrigins");
app.MapControllers();

// seed data account admin
using (IServiceScope scope = app.Services.CreateScope())
{
    IServiceProvider? services = scope.ServiceProvider;
    SeedDataAccount.SeedAsync(services).Wait();
}
app.Run();
