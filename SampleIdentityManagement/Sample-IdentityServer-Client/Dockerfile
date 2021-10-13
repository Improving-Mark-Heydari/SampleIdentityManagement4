#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["Sample-IdentityServer-Client/Sample-IdentityServer-Client.csproj", "Sample-IdentityServer-Client/"]
RUN dotnet restore "Sample-IdentityServer-Client/Sample-IdentityServer-Client.csproj"
COPY . .
WORKDIR "/src/Sample-IdentityServer-Client"
RUN dotnet build "Sample-IdentityServer-Client.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Sample-IdentityServer-Client.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Sample-IdentityServer-Client.dll"]
