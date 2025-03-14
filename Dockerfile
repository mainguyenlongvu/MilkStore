# Use .NET SDK for building the application
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build

WORKDIR /source

# Copy solution file and project files
COPY MilkStore.sln .
COPY ./MilkStore.Contract.Repositories ./MilkStore.Contract.Repositories
COPY ./MilkStore.Core ./MilkStore.Core
COPY ./MilkStore.ModelViews ./MilkStore.ModelViews
COPY ./MilkStore.Repositories ./MilkStore.Repositories
COPY ./MilkStore.Contract.Services ./MilkStore.Contract.Services
COPY ./MilkStore.Services ./MilkStore.Services
COPY ./MilkStore.API ./MilkStore.API

# Restore dependencies
RUN dotnet restore

# Build the application
WORKDIR /source/MilkStore.API
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet publish ./MilkStore.API.csproj --use-current-runtime --self-contained false -o /app

# Use minimal runtime for final image
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS final
WORKDIR /app

# Enable globalization and time zones
RUN apk add --no-cache icu-libs tzdata
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false

# Copy published app
COPY --from=build /app .

# Switch to non-root user
USER app

ENTRYPOINT ["dotnet", "MilkStore.API.dll"]
