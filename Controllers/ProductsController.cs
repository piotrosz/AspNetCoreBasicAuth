using AspNetCoreBasicAuth.Data;
using AspNetCoreBasicAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AspNetCoreBasicAuth.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class ProductsController(ApplicationDbContext applicationDbContext) : ControllerBase
{
    [HttpGet]
    [Authorize(Roles = "Administrator, User")]
    public async Task<IActionResult> GetProducts()
    {
        var products = await applicationDbContext.Products.ToListAsync();
        return Ok(products);
    }

    [HttpPost]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> AddProduct(Product product)
    {
        await applicationDbContext.Products.AddAsync(product);
        await applicationDbContext.SaveChangesAsync();
        return Ok();
    }
}