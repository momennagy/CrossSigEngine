# syntax=docker/dockerfile:1

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore "CrossSigEngine.sln"
RUN dotnet publish "CrossSigEngine.Web/CrossSigEngine.Web.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
# Optionally set a default port
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
# Install curl for container healthchecks
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "CrossSigEngine.Web.dll"]
